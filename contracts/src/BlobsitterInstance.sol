// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {MMR} from "./libraries/MMR.sol";
import {ISP1Verifier} from "./interfaces/ISP1Verifier.sol";

/// Minimal ERC-1271 surface the instance needs (§11.3).
interface IERC1271 {
    function isValidSignature(bytes32 digest, bytes calldata signature)
        external
        view
        returns (bytes4);
}

/// The blobsitter instance template — normative §11–§13, §16.
///
/// IMMUTABLE POST-DEPLOYMENT: no upgradeability, no governance, no admin roles, no
/// pausing. The publisher never holds or spends ETH — every publisher action arrives as
/// an EIP-712-signed intent carried by an arbitrary EOA and verified via ERC-1271.
///
/// Milestone scope: this file currently implements the publication core (§12.3) —
/// declareFor, setAppPointer, setSuccessor. Provider lifecycle (§12.4), challenges
/// (§12.5), custody proofs (§12.6), and the paymaster (§15) land in later milestones;
/// the paymaster reimbursement hook is a documented no-op until then.
contract BlobsitterInstance {
    // ---------------------------------------------------------------------------
    // §16 errors (publication subset). Identity is normative; tests match selectors.
    // ---------------------------------------------------------------------------
    error BadSignature();
    error WrongNonce(uint64 expected);
    error IntentExpired(uint64 deadline);
    error NotDesignatedCarrier(address want);
    error ZeroAddress();
    error EmptyUpdate();
    error BlobCountMismatch(uint256 expected);
    error BlobHashMismatch(uint256 index);
    error UnexpectedExtraBlob();
    error SubtreeCountMismatch(uint256 expected);
    error PointEvaluationFailed(uint256 blobIndex);
    error InvalidEquivalenceProof();
    error SuccessorAlreadySet();

    // ---------------------------------------------------------------------------
    // §12.8 events (publication subset) — the daemon's contract surface.
    // ---------------------------------------------------------------------------
    event Declared(
        uint64 indexed nonce,
        uint64 newLeafCount,
        bytes32[] blobVersionedHashes,
        bytes32[] newSubtreePeaks,
        bytes32 appPointer,
        address carrier
    );
    event AppPointerSet(uint64 indexed nonce, bytes32 pointer);
    event SuccessorSet(address target);

    // ---------------------------------------------------------------------------
    // §11 EIP-712. Typehash strings are exact and single-line (§11.2 wraps them for
    // display only); golden truth is vectors/eip712.json.
    // ---------------------------------------------------------------------------
    bytes32 private constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 private constant DECLARATION_TYPEHASH = keccak256(
        "Declaration(uint64 nonce,uint64 deadline,bytes32[] blobVersionedHashes,bytes32[] newSubtreePeaks,uint64 newLeafCount,address designatedCarrier,bytes32 appPointer)"
    );
    bytes32 private constant SET_APP_POINTER_TYPEHASH =
        keccak256("SetAppPointer(uint64 nonce,uint64 deadline,bytes32 appPointer)");
    bytes32 private constant SET_SUCCESSOR_TYPEHASH =
        keccak256("SetSuccessor(uint64 nonce,uint64 deadline,address successor)");
    bytes32 private constant NAME_HASH = keccak256("blobsitter");
    bytes32 private constant VERSION_HASH = keccak256("1");
    bytes4 private constant ERC1271_MAGIC = 0x1626ba7e;

    /// §11.2 Declaration — field order matches the typehash exactly.
    struct Declaration {
        uint64 nonce;
        uint64 deadline;
        bytes32[] blobVersionedHashes;
        bytes32[] newSubtreePeaks;
        uint64 newLeafCount;
        address designatedCarrier;
        bytes32 appPointer;
    }

    // ---------------------------------------------------------------------------
    // §12.1 template constants (identical in every instance).
    // ---------------------------------------------------------------------------
    uint256 public constant CHUNK_SIZE = 31;
    uint256 public constant RESPONSE_GAS_PER_CHUNK = 38_680;
    uint256 public constant RESPONSE_BASE_GAS = 21_000;
    uint256 public constant BOND_MULTIPLIER = 3;

    /// The canonical SP1VerifierGateway deployment. PROVISIONAL: pinned for real —
    /// together with the exact SP1 release — at contract freeze (§12.1). Tests etch the
    /// interface-exact mock at this address.
    address public constant SP1_VERIFIER = 0x397A5f7f3dBd538f23DE225B51f532c34448dA9B;
    /// PLACEHOLDER vkeys: the real values are the SP1 program verifying keys, computed
    /// when the circuits are built and frozen as template constants (§12.1, §14).
    bytes32 public constant EQUIVALENCE_VKEY = keccak256("blobsitter.equivalence-vkey.placeholder");
    bytes32 public constant CUSTODY_VKEY = keccak256("blobsitter.custody-vkey.placeholder");

    /// §1: r, the BLS12-381 scalar field modulus (the EIP-4844 blob field).
    uint256 private constant BLS_MODULUS =
        52435875175126190479447740508185965837690552500527637822603658699938581184513;
    /// EIP-4844 point-evaluation precompile.
    address private constant POINT_EVALUATION = address(0x0A);

    // ---------------------------------------------------------------------------
    // §12.1 constructor parameters — fixed forever at deployment. Providers MUST
    // sanity-check them before staking; the contract adds no validation the spec
    // doesn't require.
    // ---------------------------------------------------------------------------
    struct Params {
        address publisher; // ERC-1271 wallet
        uint256 stakeWei; // 2 ETH as sized
        uint64 responseWindow; // 7 d
        uint64 unbondingDelay; // 14 d
        uint64 custodyPeriod; // 30 d
        uint64 lapseGrace; // 7 d
        uint32 custodyK; // 16_384
        uint16 maxSample; // 32
        uint16 bountyBps; // 1500
        uint256 carrierTipWei; // 0.0002 ETH
        uint256 provingSubsidyWei; // 0.0005 ETH
        uint256 bucketRateWeiPerDay; // 0.05 ETH/day
        uint256 bucketCapWei; // 1.5 ETH
        uint64 dormancyWindow; // 365 d
        uint64 dormancyMinChunks; // 32_768
    }

    address public immutable publisher;
    uint256 public immutable stakeWei;
    uint64 public immutable responseWindow;
    uint64 public immutable unbondingDelay;
    uint64 public immutable custodyPeriod;
    uint64 public immutable lapseGrace;
    uint32 public immutable custodyK;
    uint16 public immutable maxSample;
    uint16 public immutable bountyBps;
    uint256 public immutable carrierTipWei;
    uint256 public immutable provingSubsidyWei;
    uint256 public immutable bucketRateWeiPerDay;
    uint256 public immutable bucketCapWei;
    uint64 public immutable dormancyWindow;
    uint64 public immutable dormancyMinChunks;

    // ---------------------------------------------------------------------------
    // §12.2 instance state (publication subset).
    // ---------------------------------------------------------------------------
    uint64 public leafCount;
    bytes32[] public peaks; // canonical order (§5.2)
    uint64 public declarationNonce;
    uint64 public appPointerNonce;
    uint64 public successorNonce;
    bytes32 public appPointer;
    address public successor; // write-once; protocol-inert (never interpreted)
    uint64 public activityCheckpointTime; // §12.7
    uint64 public activityCheckpointLeafCount;

    constructor(Params memory p) {
        publisher = p.publisher;
        stakeWei = p.stakeWei;
        responseWindow = p.responseWindow;
        unbondingDelay = p.unbondingDelay;
        custodyPeriod = p.custodyPeriod;
        lapseGrace = p.lapseGrace;
        custodyK = p.custodyK;
        maxSample = p.maxSample;
        bountyBps = p.bountyBps;
        carrierTipWei = p.carrierTipWei;
        provingSubsidyWei = p.provingSubsidyWei;
        bucketRateWeiPerDay = p.bucketRateWeiPerDay;
        bucketCapWei = p.bucketCapWei;
        dormancyWindow = p.dormancyWindow;
        dormancyMinChunks = p.dormancyMinChunks;
        // §12.7: the instance deploys empty (genesis via blobs); the dormancy clock
        // starts at deployment.
        activityCheckpointTime = uint64(block.timestamp);
        activityCheckpointLeafCount = 0;
        // Milestone 4: the paymaster is deployed here and bound one-way (§12, §15).
    }

    // ---------------------------------------------------------------------------
    // Views.
    // ---------------------------------------------------------------------------

    /// The full canonical peak list (the auto-getter for `peaks` is per-index).
    function allPeaks() external view returns (bytes32[] memory) {
        return peaks;
    }

    /// §5.3 bagged root of the current state — computed on demand, never stored.
    function root() external view returns (bytes32) {
        return MMR.bagRoot(leafCount, peaks);
    }

    /// §11.1 domain separator. Computed per call: the template is immutable but the
    /// chain can fork, and chainId must always be the executing chain's.
    function domainSeparator() public view returns (bytes32) {
        return keccak256(
            abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this))
        );
    }

    /// §11.2 Declaration digest (public so carriers and tooling can precompute).
    function declarationDigest(Declaration calldata d) public view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                DECLARATION_TYPEHASH,
                d.nonce,
                d.deadline,
                keccak256(abi.encodePacked(d.blobVersionedHashes)),
                keccak256(abi.encodePacked(d.newSubtreePeaks)),
                d.newLeafCount,
                d.designatedCarrier,
                d.appPointer
            )
        );
        return _digest(structHash);
    }

    /// §11.2 SetAppPointer digest.
    function setAppPointerDigest(uint64 nonce, uint64 deadline, bytes32 pointer)
        public
        view
        returns (bytes32)
    {
        return _digest(keccak256(abi.encode(SET_APP_POINTER_TYPEHASH, nonce, deadline, pointer)));
    }

    /// §11.2 SetSuccessor digest.
    function setSuccessorDigest(uint64 nonce, uint64 deadline, address target)
        public
        view
        returns (bytes32)
    {
        return _digest(keccak256(abi.encode(SET_SUCCESSOR_TYPEHASH, nonce, deadline, target)));
    }

    /// §8: the Fiat–Shamir evaluation point z, reduced into the BLS12-381 scalar field.
    /// The instance address makes z — and hence proofs — instance-bound; every committed
    /// quantity the equivalence statement touches appears in the preimage. Public so
    /// carriers and the publisher toolchain can precompute openings.
    function fiatShamirZ(
        bytes32[] memory blobVersionedHashes,
        bytes32[] memory priorPeaks,
        bytes32[] memory newSubtreePeaks,
        uint64 priorLeafCount,
        uint64 newLeafCount
    ) public view returns (bytes32) {
        bytes32 h = keccak256(
            abi.encodePacked(
                bytes1(0x03),
                address(this),
                blobVersionedHashes,
                priorPeaks,
                newSubtreePeaks,
                priorLeafCount,
                newLeafCount
            )
        );
        return bytes32(uint256(h) % BLS_MODULUS);
    }

    // ---------------------------------------------------------------------------
    // §12.3 publication: declareFor.
    // ---------------------------------------------------------------------------

    struct BlobOpening {
        bytes32 y;
        bytes commitment; // 48 bytes (KZG commitment)
        bytes kzgProof; // 48 bytes
    }

    function declareFor(
        Declaration calldata d,
        bytes calldata publisherSig,
        BlobOpening[] calldata openings,
        bytes calldata equivalenceProof
    ) external {
        // Check 1: intent validity.
        if (block.timestamp > d.deadline) revert IntentExpired(d.deadline);
        if (d.nonce != declarationNonce) revert WrongNonce(declarationNonce);
        if (d.designatedCarrier != address(0) && d.designatedCarrier != msg.sender) {
            revert NotDesignatedCarrier(d.designatedCarrier);
        }
        _requireValidSignature(declarationDigest(d), publisherSig);

        // Check 2: shape — the transaction carries exactly the signed blobs, and the
        // subtree peak count matches the (n, m)-determined decomposition.
        uint64 n0 = leafCount;
        if (d.newLeafCount <= n0) revert EmptyUpdate();
        uint64 m = d.newLeafCount - n0;
        uint256 blobCount = (uint256(m) + 4095) / 4096; // B = ceil(m / 4096) (§4)
        if (d.blobVersionedHashes.length != blobCount || openings.length != blobCount) {
            revert BlobCountMismatch(blobCount);
        }
        for (uint256 j = 0; j < blobCount; ++j) {
            if (blobhash(j) != d.blobVersionedHashes[j]) revert BlobHashMismatch(j);
        }
        if (blobhash(blobCount) != bytes32(0)) revert UnexpectedExtraBlob();
        uint8[] memory heights = MMR.decompose(n0, m);
        if (d.newSubtreePeaks.length != heights.length) {
            revert SubtreeCountMismatch(heights.length);
        }

        // Check 3: every blob opens to its claimed value at the Fiat–Shamir point.
        bytes32[] memory priorPeaks = peaks;
        bytes32 z =
            fiatShamirZ(d.blobVersionedHashes, priorPeaks, d.newSubtreePeaks, n0, d.newLeafCount);
        for (uint256 j = 0; j < blobCount; ++j) {
            _verifyOpening(d.blobVersionedHashes[j], z, openings[j], j);
        }

        // Check 4: the equivalence proof (blob bytes ⇔ submitted subtree roots).
        try ISP1Verifier(SP1_VERIFIER)
            .verifyProof(EQUIVALENCE_VKEY, _equivalencePublicValues(), equivalenceProof) {}
        catch {
            revert InvalidEquivalenceProof();
        }

        // Step 5: effects. The recovery log is the Declared event itself — the
        // versioned-hash history is event-only, never contract state.
        (bytes32[] memory newPeaks, uint64 n1) =
            MMR.applyUpdate(priorPeaks, n0, d.newSubtreePeaks, heights);
        peaks = newPeaks;
        leafCount = n1; // == d.newLeafCount by construction
        declarationNonce = d.nonce + 1;
        if (d.appPointer != bytes32(0)) appPointer = d.appPointer;
        // §12.7: advance the activity checkpoint if due.
        if (n1 - activityCheckpointLeafCount >= dormancyMinChunks) {
            activityCheckpointTime = uint64(block.timestamp);
            activityCheckpointLeafCount = n1;
        }
        emit Declared(
            d.nonce, n1, d.blobVersionedHashes, d.newSubtreePeaks, d.appPointer, msg.sender
        );

        // Step 6: carrier reimbursement — after all state changes.
        _reimburse(msg.sender, blobCount, true);
    }

    // ---------------------------------------------------------------------------
    // §12.3 publication: setAppPointer / setSuccessor. Same pattern each: deadline,
    // own nonce, ERC-1271, effect, event, paymaster-reimbursed.
    // ---------------------------------------------------------------------------

    function setAppPointer(uint64 nonce, uint64 deadline, bytes32 pointer, bytes calldata sig)
        external
    {
        if (block.timestamp > deadline) revert IntentExpired(deadline);
        if (nonce != appPointerNonce) revert WrongNonce(appPointerNonce);
        _requireValidSignature(setAppPointerDigest(nonce, deadline, pointer), sig);

        appPointerNonce = nonce + 1;
        appPointer = pointer;
        emit AppPointerSet(nonce, pointer);
        _reimburse(msg.sender, 0, false);
    }

    function setSuccessor(uint64 nonce, uint64 deadline, address target, bytes calldata sig)
        external
    {
        if (block.timestamp > deadline) revert IntentExpired(deadline);
        if (nonce != successorNonce) revert WrongNonce(successorNonce);
        _requireValidSignature(setSuccessorDigest(nonce, deadline, target), sig);
        // §12.3: additionally write-once and nonzero.
        if (successor != address(0)) revert SuccessorAlreadySet();
        if (target == address(0)) revert ZeroAddress();

        successorNonce = nonce + 1;
        successor = target;
        emit SuccessorSet(target);
        _reimburse(msg.sender, 0, false);
    }

    // ---------------------------------------------------------------------------
    // Internals.
    // ---------------------------------------------------------------------------

    /// `keccak256(0x1901 ‖ domainSeparator ‖ structHash)` (§11.1).
    function _digest(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", domainSeparator(), structHash));
    }

    /// §11.3: the publisher wallet must return the ERC-1271 magic value for the digest.
    /// Any failure — wrong value, revert, malformed return, no code at the wallet — is
    /// BadSignature. Low-level staticcall: a high-level call would revert without data on
    /// a codeless publisher (extcodesize check) instead of reporting the normative error.
    function _requireValidSignature(bytes32 digest, bytes calldata sig) internal view {
        (bool ok, bytes memory ret) =
            publisher.staticcall(abi.encodeCall(IERC1271.isValidSignature, (digest, sig)));
        if (!ok || ret.length < 32 || abi.decode(ret, (bytes32)) != bytes32(ERC1271_MAGIC)) {
            revert BadSignature();
        }
    }

    /// §12.3 check 3: the EIP-4844 point-evaluation precompile with input
    /// `vh ‖ z ‖ y ‖ commitment ‖ kzgProof` (192 bytes). A wrong-length commitment or
    /// proof simply yields a non-192-byte input, which the precompile rejects.
    function _verifyOpening(bytes32 vh, bytes32 z, BlobOpening calldata o, uint256 blobIndex)
        private
        view
    {
        (bool ok,) =
            POINT_EVALUATION.staticcall(abi.encodePacked(vh, z, o.y, o.commitment, o.kzgProof));
        if (!ok) revert PointEvaluationFailed(blobIndex);
    }

    /// §14 (circuit statements and publicValues byte layouts) is RESERVED and unwritten,
    /// and inventing an encoding is forbidden — a silent guess becomes permanent. Until
    /// §14 lands, the instance passes empty publicValues and the mock verifier validates
    /// only (vkey, proof).
    /// TODO(§14): encode the equivalence statement's public values exactly as specified.
    /// This function body is the only place that changes; no call site moves.
    function _equivalencePublicValues() private pure returns (bytes memory) {
        return "";
    }

    /// §12.3 step 6 / §15 carrier reimbursement hook. Milestone 4 deploys the paymaster
    /// in the constructor and wires this up (gas-capped call, failure ignored,
    /// reentrancy-guarded, strictly after all state changes). Until then: no-op.
    function _reimburse(address carrier, uint256 numBlobs, bool isDeclaration) internal {
        // no-op until milestone 4 (paymaster)
    }
}
