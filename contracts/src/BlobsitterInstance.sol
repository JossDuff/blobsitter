// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {MMR} from "./libraries/MMR.sol";
import {ISP1Verifier} from "./interfaces/ISP1Verifier.sol";

/// Minimal ERC-1271 surface the instance needs to verify publisher intent signatures.
interface IERC1271 {
    function isValidSignature(bytes32 digest, bytes calldata signature)
        external
        view
        returns (bytes4);
}

/// The blobsitter instance template.
///
/// IMMUTABLE POST-DEPLOYMENT: no upgradeability, no governance, no admin roles, no
/// pausing. The publisher never holds or spends ETH — every publisher action arrives as
/// an EIP-712-signed intent carried by an arbitrary EOA and verified via ERC-1271.
///
/// Milestone scope: the publication core, the provider lifecycle, possession challenges,
/// custody proofs (commit/prove/escape/lapse), and the push-with-pull-fallback payout
/// pattern are implemented. The paymaster is milestone 4 — its reimbursement hook is a
/// documented no-op and slash remainders accumulate in pendingSlashRemainders until then.
contract BlobsitterInstance {
    // ---------------------------------------------------------------------------
    // Errors (publication subset). Names and argument types are fixed by the normative
    // spec; tests match on exact selectors.
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
    error NothingClaimable();
    error PayoutFailed();
    error WrongStakeAmount(uint256 expected);
    error UnknownProvider(uint64 providerId);
    error NotOperator(uint64 providerId);
    error NotActive(uint64 providerId);
    error NotUnbonding(uint64 providerId);
    error UnbondingDelayActive(uint64 until);
    error OpenChallengesRemain(uint32 count);
    error ChallengeWindowClosed();
    error NoIndices();
    error TooManyIndices(uint16 max);
    error IndexOutOfRange(uint64 index, uint64 leafCount);
    error BondTooSmall(uint256 required);
    error UnknownChallenge(uint64 challengeId);
    error AlreadyResolved(uint64 challengeId);
    error ResponseWindowClosed(uint64 deadline);
    error ResponseWindowStillOpen(uint64 deadline);
    error IndicesMismatch();
    error ProofCountMismatch(uint256 expected);
    error PinMismatch();
    error InvalidInclusionProof(uint256 sampleIndex);
    error ProviderSlashed(uint64 providerId);
    error AlreadyCommitted(uint64 period);
    error NoCommit();
    error CommitFromEarlierPeriod(uint64 committed, uint64 current);
    error InvalidCustodyProof();
    error NotLapsable(uint64 lapsableAt);

    // ---------------------------------------------------------------------------
    // Events (publication subset) — the contract surface off-chain daemons index to
    // reconstruct history; the blob versioned-hash log in particular lives only here.
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
    event PayoutDeferred(address indexed recipient, uint256 amount);
    event Claimed(address indexed recipient, uint256 amount);
    event Staked(uint64 indexed providerId, address operator, address withdrawal);
    event UnbondingInitiated(uint64 indexed providerId, bytes32 exitRoot, uint64 exitLeafCount);
    event Withdrawn(uint64 indexed providerId);
    event Announced(string url);
    event Retracted();
    event ChallengeOpened(
        uint64 indexed challengeId,
        uint64 indexed providerId,
        uint64[] indices,
        uint256 bond,
        bytes32 pinnedRoot,
        uint64 pinnedLeafCount,
        uint64 deadline
    );
    event ChallengeAnswered(uint64 indexed challengeId);
    event ChallengeRefunded(uint64 indexed challengeId);
    event Slashed(uint64 indexed providerId, SlashCause cause, address executor);
    event CustodyCommitted(
        uint64 indexed providerId, uint64 period, bytes32 seed, bytes32 root, uint64 leafCount
    );
    event CustodyProven(uint64 indexed providerId, uint64 period, bool degraded);

    // ---------------------------------------------------------------------------
    // EIP-712 machinery. Typehash strings are exact and single-line (any wrapping in
    // documents is for display only); golden truth is vectors/eip712.json.
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

    /// A signed publication intent — field order matches the typehash exactly.
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
    // Template constants — identical in every instance of the template.
    // ---------------------------------------------------------------------------
    uint256 public constant CHUNK_SIZE = 31;
    uint256 public constant RESPONSE_GAS_PER_CHUNK = 38_680;
    uint256 public constant RESPONSE_BASE_GAS = 21_000;
    uint256 public constant BOND_MULTIPLIER = 3;

    /// The canonical SP1VerifierGateway deployment. PROVISIONAL: pinned for real —
    /// together with the exact SP1 release — at contract freeze. Tests etch the
    /// interface-exact mock at this address.
    address public constant SP1_VERIFIER = 0x397A5f7f3dBd538f23DE225B51f532c34448dA9B;
    /// PLACEHOLDER vkeys: the real values are the SP1 program verifying keys, computed
    /// when the circuits are built and then frozen as template constants.
    bytes32 public constant EQUIVALENCE_VKEY = keccak256("blobsitter.equivalence-vkey.placeholder");
    bytes32 public constant CUSTODY_VKEY = keccak256("blobsitter.custody-vkey.placeholder");

    /// r, the BLS12-381 scalar field modulus — the field EIP-4844 blob elements live in.
    uint256 private constant BLS_MODULUS =
        52435875175126190479447740508185965837690552500527637822603658699938581184513;
    /// EIP-4844 point-evaluation precompile.
    address private constant POINT_EVALUATION = address(0x0A);

    // ---------------------------------------------------------------------------
    // Constructor parameters — fixed forever at deployment. Providers MUST sanity-check
    // them before staking; the contract adds no validation the spec doesn't require.
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
    // Instance state (publication subset).
    // ---------------------------------------------------------------------------
    uint64 public leafCount;
    bytes32[] public peaks; // canonical order: descending height, oldest subtree first
    uint64 public declarationNonce;
    uint64 public appPointerNonce;
    uint64 public successorNonce;
    bytes32 public appPointer;
    address public successor; // write-once; protocol-inert (never interpreted)
    // Dormancy tracking: when activity was last checkpointed, and the leaf count then.
    // Declarations that grow the MMR by enough chunks restart the clock (see declareFor).
    uint64 public activityCheckpointTime;
    uint64 public activityCheckpointLeafCount;
    /// Pull-fallback ledger: balances of failed pushes park here; claim() drains.
    mapping(address => uint256) public claimable;

    // ---------------------------------------------------------------------------
    // Provider state.
    // ---------------------------------------------------------------------------

    enum ProviderStatus {
        NONE,
        ACTIVE,
        UNBONDING,
        EXITED,
        SLASHED
    }

    struct Provider {
        address operator; // immutable; hot key: proofs, responses, initiate unbonding
        address withdrawal; // immutable; the ONLY address the stake can be paid to
        ProviderStatus status;
        uint64 anchor; // stake time; custody periods count from here (M3)
        uint64 lastProvenPlusOne; // spec's lastProven + 1 (0 encodes −1); custody, M3
        bool lastDegraded; // custody, M3
        uint64 commitPeriodPlusOne; // custody commit (0 = none); M3
        bytes32 commitSeed;
        bytes32 commitRoot;
        uint64 commitLeafCount;
        uint64 unbondingAt; // 0 while ACTIVE
        bytes32 exitRoot; // Root(n, peaks) snapshotted at initiateUnbonding
        uint64 exitLeafCount;
        uint32 openChallenges; // blocks withdraw() while nonzero
    }

    uint64 public nextProviderId = 1; // providerId 0 means "none" and is never assigned
    mapping(uint64 => Provider) internal providers;

    // ---------------------------------------------------------------------------
    // Challenge state.
    // ---------------------------------------------------------------------------

    enum SlashCause {
        CHALLENGE_TIMEOUT,
        LAPSE // custody lapse — arrives in milestone 3
    }

    struct Challenge {
        uint64 providerId;
        address challenger;
        uint256 bond;
        uint64 openedAt;
        bytes32 pinnedRoot; // Root(n, peaks) at open — or the provider's exitRoot
        uint64 pinnedLeafCount;
        bytes32 indicesHash; // keccak256(abi.encodePacked(uint64[] indices))
        uint16 k;
        bool resolved;
    }

    /// Challenge-response payload: the raw chunk plus its Merkle sibling path, ordered
    /// bottom-up (the leaf's sibling first).
    struct ChunkProof {
        bytes31 chunk;
        bytes32[] path;
    }

    uint64 public nextChallengeId;
    mapping(uint64 => Challenge) internal challengeRecords;

    /// Slash remainders (stake − bounty) held by the instance.
    /// TODO(M4): route through paymaster.absorbSlash() once the constructor deploys
    /// the paymaster; this accumulator then disappears. Revisit before any deployment
    /// freeze.
    uint256 public pendingSlashRemainders;

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
        // The instance deploys empty — genesis content arrives via ordinary blob
        // declarations — and the dormancy clock starts ticking at deployment.
        activityCheckpointTime = uint64(block.timestamp);
        activityCheckpointLeafCount = 0;
        // Milestone 4: the paymaster is deployed here and bound one-way.
    }

    // ---------------------------------------------------------------------------
    // Views.
    // ---------------------------------------------------------------------------

    /// The full canonical peak list (the auto-getter for `peaks` is per-index).
    function allPeaks() external view returns (bytes32[] memory) {
        return peaks;
    }

    /// Bagged root of the current state (a single hash binding the leaf count and every
    /// peak) — computed on demand, never stored.
    function root() external view returns (bytes32) {
        return MMR.bagRoot(leafCount, peaks);
    }

    /// EIP-712 domain separator. Computed per call: the template is immutable but the
    /// chain can fork, and chainId must always be the executing chain's.
    function domainSeparator() public view returns (bytes32) {
        return keccak256(
            abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this))
        );
    }

    /// EIP-712 Declaration digest (public so carriers and tooling can precompute).
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

    /// EIP-712 SetAppPointer digest.
    function setAppPointerDigest(uint64 nonce, uint64 deadline, bytes32 pointer)
        public
        view
        returns (bytes32)
    {
        return _digest(keccak256(abi.encode(SET_APP_POINTER_TYPEHASH, nonce, deadline, pointer)));
    }

    /// EIP-712 SetSuccessor digest.
    function setSuccessorDigest(uint64 nonce, uint64 deadline, address target)
        public
        view
        returns (bytes32)
    {
        return _digest(keccak256(abi.encode(SET_SUCCESSOR_TYPEHASH, nonce, deadline, target)));
    }

    /// The Fiat–Shamir evaluation point z, reduced into the BLS12-381 scalar field. The
    /// 0x03 domain-tag byte keeps this hash distinct from the MMR leaf/node/root hashes.
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
    // Publication: declareFor.
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
        uint256 blobCount = (uint256(m) + 4095) / 4096; // ceil(m / 4096): 4096 chunks/blob
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
        // Record activity: once enough new chunks have accumulated since the last
        // checkpoint, restart the dormancy clock.
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
    // Publication: setAppPointer / setSuccessor. Same pattern each: deadline, own
    // nonce, ERC-1271, effect, event, paymaster-reimbursed.
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
        // Beyond the common intent checks: the successor pointer is write-once (it can
        // never be changed once set) and must be nonzero.
        if (successor != address(0)) revert SuccessorAlreadySet();
        if (target == address(0)) revert ZeroAddress();

        successorNonce = nonce + 1;
        successor = target;
        emit SuccessorSet(target);
        _reimburse(msg.sender, 0, false);
    }

    // ---------------------------------------------------------------------------
    // Provider lifecycle.
    // ---------------------------------------------------------------------------

    /// The full provider record (the mapping is internal; a flat auto-getter would be
    /// unwieldy with the nested custody fields).
    function getProvider(uint64 providerId) external view returns (Provider memory) {
        return providers[providerId];
    }

    /// Bonded tier entry. The caller is irrelevant thereafter: the record is keyed by
    /// providerId, operated by `operator`, and pays out only to `withdrawal`.
    function stake(address operator, address withdrawal)
        external
        payable
        returns (uint64 providerId)
    {
        if (msg.value != stakeWei) revert WrongStakeAmount(stakeWei);
        if (operator == address(0) || withdrawal == address(0)) revert ZeroAddress();
        providerId = nextProviderId++;
        Provider storage p = providers[providerId];
        p.operator = operator;
        p.withdrawal = withdrawal;
        p.status = ProviderStatus.ACTIVE;
        p.anchor = uint64(block.timestamp);
        // lastProvenPlusOne = 0 encodes the spec's lastProven = −1.
        emit Staked(providerId, operator, withdrawal);
    }

    /// Snapshot the exit pin and end custody obligations. Always allowed while ACTIVE.
    function initiateUnbonding(uint64 providerId) external {
        Provider storage p = _provider(providerId);
        if (msg.sender != p.operator) revert NotOperator(providerId);
        if (p.status != ProviderStatus.ACTIVE) revert NotActive(providerId);
        p.status = ProviderStatus.UNBONDING;
        p.unbondingAt = uint64(block.timestamp);
        p.exitRoot = MMR.bagRoot(leafCount, peaks);
        p.exitLeafCount = leafCount;
        // Custody obligations end: void any pending commit (fields live from M3 on),
        // which also cancels lapse eligibility.
        p.commitPeriodPlusOne = 0;
        p.commitSeed = 0;
        p.commitRoot = 0;
        p.commitLeafCount = 0;
        emit UnbondingInitiated(providerId, p.exitRoot, p.exitLeafCount);
    }

    /// Release the stake — to the withdrawal address only — once the delay has passed
    /// and no challenge is open. Anyone may call.
    function withdraw(uint64 providerId) external {
        Provider storage p = _provider(providerId);
        if (p.status != ProviderStatus.UNBONDING) revert NotUnbonding(providerId);
        uint64 until = p.unbondingAt + unbondingDelay;
        if (block.timestamp < until) revert UnbondingDelayActive(until);
        if (p.openChallenges != 0) revert OpenChallengesRemain(p.openChallenges);
        p.status = ProviderStatus.EXITED;
        emit Withdrawn(providerId);
        _payout(p.withdrawal, stakeWei);
    }

    /// Mirror tier: events only — no state, no stake, no protocol standing.
    function announce(string calldata url) external {
        emit Announced(url);
    }

    function retract() external {
        emit Retracted();
    }

    /// Provider record lookup; NONE means the id was never assigned.
    function _provider(uint64 providerId) internal view returns (Provider storage p) {
        p = providers[providerId];
        if (p.status == ProviderStatus.NONE) revert UnknownProvider(providerId);
    }

    // ---------------------------------------------------------------------------
    // Custody proofs: each period (30 days as sized, counted from the provider's
    // stake time), an active provider commits to a randomness seed and a snapshot of
    // the dataset, then proves possession — normally with a succinct proof over
    // 16,384 sampled chunks, or through the escape hatch: revealing the raw chunks
    // at 32 contract-derived positions with Merkle proofs. The escape hatch is pure
    // keccak and calldata, and must stay that way forever: it is the path that
    // still works when all proving infrastructure has rotted.
    // ---------------------------------------------------------------------------

    /// The custody period index for a provider at the current time: whole periods
    /// elapsed since their stake-time anchor.
    function custodyPeriodIndex(uint64 providerId) public view returns (uint64) {
        Provider storage p = _provider(providerId);
        return uint64((block.timestamp - p.anchor) / custodyPeriod);
    }

    /// The sampled chunk position for ordinal j: a keccak (0x04 domain tag) over the
    /// instance address, the committed seed, the provider id, and j, reduced modulo
    /// the snapshot's leaf count. The provider id stops one proof from serving two
    /// providers; the instance address stops it from serving two instances that
    /// happen to share a seed. Public so operators can precompute their reveals.
    /// Callers must ensure leafCount > 0.
    function custodyIndex(bytes32 seed, uint64 providerId, uint64 j, uint64 leafCount)
        public
        view
        returns (uint64)
    {
        return uint64(
            uint256(keccak256(abi.encodePacked(bytes1(0x04), address(this), seed, providerId, j)))
                % leafCount
        );
    }

    /// Open the current period's proof window: snapshot the randomness seed and the
    /// dataset state. The FIRST commit of a period is binding — the seed can never be
    /// re-rolled — but a leftover commit from an earlier, already-missed period is
    /// simply overwritten.
    function beginProof(uint64 providerId) external {
        Provider storage p = _provider(providerId);
        if (msg.sender != p.operator) revert NotOperator(providerId);
        if (p.status != ProviderStatus.ACTIVE) revert NotActive(providerId);
        uint64 period = custodyPeriodIndex(providerId);
        if (p.commitPeriodPlusOne != 0 && p.commitPeriodPlusOne - 1 == period) {
            revert AlreadyCommitted(period);
        }
        p.commitPeriodPlusOne = period + 1;
        p.commitSeed = bytes32(block.prevrandao);
        p.commitRoot = MMR.bagRoot(leafCount, peaks);
        p.commitLeafCount = leafCount;
        emit CustodyCommitted(providerId, period, p.commitSeed, p.commitRoot, p.commitLeafCount);
    }

    /// Prove the committed period with a succinct proof. Must land in the same period
    /// as its commit — a commit whose period has passed is worthless and the period
    /// is simply missed.
    function submitProof(uint64 providerId, bytes calldata proof) external {
        Provider storage p = _provider(providerId);
        uint64 period = _submitGuards(p, providerId);
        try ISP1Verifier(SP1_VERIFIER).verifyProof(CUSTODY_VKEY, _custodyPublicValues(), proof) {}
        catch {
            revert InvalidCustodyProof();
        }
        _acceptProof(p, providerId, period, false);
    }

    /// The degraded path: reveal the raw chunks at the 32 contract-derived positions,
    /// each with a Merkle inclusion proof against the committed snapshot (supplied as
    /// calldata and re-bagged against the stored one-word pin). An empty snapshot is
    /// vacuously proven with zero reveals — there is nothing to sample from nothing,
    /// which keeps a provider who staked before the first declaration curable.
    function submitProofEscape(
        uint64 providerId,
        uint64 n,
        bytes32[] calldata pinnedPeaks,
        ChunkProof[] calldata reveals
    ) external {
        Provider storage p = _provider(providerId);
        uint64 period = _submitGuards(p, providerId);
        bytes32[] memory peaksMem = pinnedPeaks;
        if (n != p.commitLeafCount || MMR.bagRoot(n, peaksMem) != p.commitRoot) {
            revert PinMismatch();
        }
        uint256 required = n == 0 ? 0 : maxSample;
        if (reveals.length != required) revert ProofCountMismatch(required);
        bytes32 seed = p.commitSeed;
        for (uint64 j = 0; j < reveals.length; ++j) {
            uint64 idx = custodyIndex(seed, providerId, j, n);
            if (!MMR.verify(reveals[j].chunk, idx, reveals[j].path, n, peaksMem)) {
                revert InvalidInclusionProof(j);
            }
        }
        _acceptProof(p, providerId, period, true);
    }

    /// Shared submit guards; returns the current (== committed) period.
    function _submitGuards(Provider storage p, uint64 providerId) private view returns (uint64) {
        if (msg.sender != p.operator) revert NotOperator(providerId);
        if (p.status != ProviderStatus.ACTIVE) revert NotActive(providerId);
        if (p.commitPeriodPlusOne == 0) revert NoCommit();
        uint64 committed = p.commitPeriodPlusOne - 1;
        uint64 current = custodyPeriodIndex(providerId);
        if (committed != current) revert CommitFromEarlierPeriod(committed, current);
        return current;
    }

    /// An accepted proof (either path) marks the period proven and voids the commit.
    function _acceptProof(Provider storage p, uint64 providerId, uint64 period, bool degraded)
        private
    {
        p.lastProvenPlusOne = period + 1;
        p.lastDegraded = degraded;
        p.commitPeriodPlusOne = 0;
        p.commitSeed = 0;
        p.commitRoot = 0;
        p.commitLeafCount = 0;
        emit CustodyProven(providerId, period, degraded);
    }

    /// A provider's derived custody health. Never stored — computed from the period
    /// arithmetic on demand. Meanings: CURRENT — no completed period unproven; STALE —
    /// one completed period missed (informational); LAPSE_ELIGIBLE — two consecutive
    /// misses, but inside the grace window where only the provider can act; LAPSABLE —
    /// anyone may slash via lapse(). NONE — the provider is not ACTIVE (unbonding,
    /// exited, slashed, or unknown ids have no custody obligations).
    enum CustodyStatus {
        NONE,
        CURRENT,
        STALE,
        LAPSE_ELIGIBLE,
        LAPSABLE
    }

    function custodyStatus(uint64 providerId) external view returns (CustodyStatus) {
        Provider storage p = providers[providerId];
        if (p.status != ProviderStatus.ACTIVE) return CustodyStatus.NONE;
        uint64 period = uint64((block.timestamp - p.anchor) / custodyPeriod);
        // q is the last proven period, one-off-stored so that 0 encodes "none yet".
        if (period + 1 <= p.lastProvenPlusOne + 1) return CustodyStatus.CURRENT; // p <= q+1
        if (period + 1 == p.lastProvenPlusOne + 2) return CustodyStatus.STALE; // p == q+2
        // Two consecutive misses: the clock to public slashing started when the second
        // missed period completed.
        (, uint256 lapsableAt) = _lapseTimes(p);
        return block.timestamp < lapsableAt ? CustodyStatus.LAPSE_ELIGIBLE : CustodyStatus.LAPSABLE;
    }

    /// Slash a provider who has missed two consecutive custody periods and let the
    /// grace window pass uncured. Anyone may call; the bounty pays the caller and the
    /// remainder is held for the future paymaster. An accepted proof at ANY point
    /// before this executes resets the clock — cure always wins if it lands first.
    function lapse(uint64 providerId) external {
        Provider storage p = _provider(providerId);
        // Unbonding and slashed providers are immune: their custody obligations ended.
        if (p.status != ProviderStatus.ACTIVE) revert NotActive(providerId);
        (uint256 eligibleAt, uint256 lapsableAt) = _lapseTimes(p);
        if (block.timestamp < eligibleAt) revert NotLapsable(0); // not even two misses yet
        if (block.timestamp < lapsableAt) revert NotLapsable(uint64(lapsableAt)); // grace

        p.status = ProviderStatus.SLASHED;
        uint256 bounty = (stakeWei * bountyBps) / 10_000;
        // Remainder held pending the paymaster (see pendingSlashRemainders TODO).
        pendingSlashRemainders += stakeWei - bounty;
        emit Slashed(providerId, SlashCause.LAPSE, msg.sender);
        _payout(msg.sender, bounty);
    }

    /// The two lapse thresholds: eligibility opens the instant the second consecutive
    /// missed period completes (anchor + (lastProven + 3) whole periods), and public
    /// slashability follows one grace window later. uint256 math so absurd constructor
    /// parameters cannot overflow the products.
    function _lapseTimes(Provider storage p)
        private
        view
        returns (uint256 eligibleAt, uint256 lapsableAt)
    {
        // lastProvenPlusOne stores q+1, so q+3 whole periods is lastProvenPlusOne + 2.
        eligibleAt = uint256(p.anchor) + (uint256(p.lastProvenPlusOne) + 2) * uint256(custodyPeriod);
        lapsableAt = eligibleAt + lapseGrace;
    }

    /// The custody circuit's public-input byte layout is deliberately not yet
    /// specified, and inventing one is forbidden — a silent guess becomes permanent.
    /// Until the circuit spec is written this returns empty bytes and the mock
    /// verifier validates only (vkey, proof).
    /// TODO(spec): encode the custody statement's public values exactly as specified
    /// (they bind instance, providerId, seed, root, leafCount, and the sample count).
    /// This function body is the only place that changes; no call site moves.
    function _custodyPublicValues() private pure returns (bytes memory) {
        return "";
    }

    // ---------------------------------------------------------------------------
    // Possession challenges.
    // ---------------------------------------------------------------------------

    /// The full challenge record.
    function getChallenge(uint64 challengeId) external view returns (Challenge memory) {
        return challengeRecords[challengeId];
    }

    /// Open a possession challenge against a provider. Pin: the CURRENT root for an
    /// ACTIVE provider, the exit snapshot for an in-window UNBONDING one (an exiting
    /// provider is never answerable for post-initiation data). Duplicate indices are
    /// permitted — they only waste the challenger's bond.
    function challenge(uint64 providerId, uint64[] calldata indices)
        external
        payable
        returns (uint64 challengeId)
    {
        Provider storage p = _provider(providerId);
        bytes32 pinnedRoot;
        uint64 pinnedLeafCount;
        if (p.status == ProviderStatus.ACTIVE) {
            pinnedRoot = MMR.bagRoot(leafCount, peaks);
            pinnedLeafCount = leafCount;
        } else if (
            p.status == ProviderStatus.UNBONDING && block.timestamp < p.unbondingAt + unbondingDelay
        ) {
            pinnedRoot = p.exitRoot;
            pinnedLeafCount = p.exitLeafCount;
        } else {
            revert ChallengeWindowClosed();
        }

        if (indices.length == 0) revert NoIndices();
        if (indices.length > maxSample) revert TooManyIndices(maxSample);
        for (uint256 j = 0; j < indices.length; ++j) {
            if (indices[j] >= pinnedLeafCount) {
                revert IndexOutOfRange(indices[j], pinnedLeafCount);
            }
        }
        // Bond: BOND_MULTIPLIER × the worst-case response gas at the current basefee.
        uint256 required = BOND_MULTIPLIER
            * (indices.length * RESPONSE_GAS_PER_CHUNK + RESPONSE_BASE_GAS) * block.basefee;
        if (msg.value < required) revert BondTooSmall(required);

        challengeId = nextChallengeId++;
        Challenge storage c = challengeRecords[challengeId];
        c.providerId = providerId;
        c.challenger = msg.sender;
        c.bond = msg.value;
        c.openedAt = uint64(block.timestamp);
        c.pinnedRoot = pinnedRoot;
        c.pinnedLeafCount = pinnedLeafCount;
        c.indicesHash = keccak256(abi.encodePacked(indices));
        c.k = uint16(indices.length);
        p.openChallenges += 1;
        emit ChallengeOpened(
            challengeId,
            providerId,
            indices,
            msg.value,
            pinnedRoot,
            pinnedLeafCount,
            uint64(block.timestamp) + responseWindow
        );
    }

    /// Answer a challenge with the raw chunks and Merkle inclusion proofs against the
    /// pinned state, whose peak list arrives as calldata and is re-bagged against the
    /// stored one-word pin. Full index set in one call; an invalid response reverts and
    /// the challenge stays open (no partial credit).
    function respond(
        uint64 challengeId,
        uint64[] calldata indices,
        uint64 n,
        bytes32[] calldata pinnedPeaks,
        ChunkProof[] calldata proofs
    ) external {
        Challenge storage c = _challenge(challengeId);
        Provider storage p = providers[c.providerId];
        // Guard order is fixed by the normative spec (it decides which error fires
        // first): operator; window; unresolved; not slashed.
        if (msg.sender != p.operator) revert NotOperator(c.providerId);
        uint64 deadline = c.openedAt + responseWindow;
        if (block.timestamp >= deadline) revert ResponseWindowClosed(deadline);
        if (c.resolved) revert AlreadyResolved(challengeId);
        if (p.status == ProviderStatus.SLASHED) revert ProviderSlashed(c.providerId);

        if (proofs.length != c.k) revert ProofCountMismatch(c.k);
        if (keccak256(abi.encodePacked(indices)) != c.indicesHash) revert IndicesMismatch();
        bytes32[] memory peaksMem = pinnedPeaks;
        if (n != c.pinnedLeafCount || MMR.bagRoot(n, peaksMem) != c.pinnedRoot) {
            revert PinMismatch();
        }
        for (uint256 j = 0; j < proofs.length; ++j) {
            if (!MMR.verify(proofs[j].chunk, indices[j], proofs[j].path, n, peaksMem)) {
                revert InvalidInclusionProof(j);
            }
        }

        c.resolved = true;
        p.openChallenges -= 1;
        emit ChallengeAnswered(challengeId);
        // Bond to the OPERATOR: it compensates response gas the hot wallet paid, and
        // keeps the hot wallet fueled without touching cold keys.
        _payout(p.operator, c.bond);
    }

    /// Resolve an unanswered challenge after its window: slash the provider (first
    /// time) with the bounty to the challenger, or refund only (provider already
    /// slashed — watchdogs aren't punished for piling onto a dying provider).
    function resolveTimeout(uint64 challengeId) external {
        Challenge storage c = _challenge(challengeId);
        if (c.resolved) revert AlreadyResolved(challengeId);
        uint64 deadline = c.openedAt + responseWindow;
        if (block.timestamp < deadline) revert ResponseWindowStillOpen(deadline);

        Provider storage p = providers[c.providerId];
        c.resolved = true;
        p.openChallenges -= 1;
        if (p.status != ProviderStatus.SLASHED) {
            p.status = ProviderStatus.SLASHED;
            uint256 bounty = (stakeWei * bountyBps) / 10_000;
            // Remainder held pending the paymaster (see pendingSlashRemainders TODO).
            pendingSlashRemainders += stakeWei - bounty;
            emit Slashed(c.providerId, SlashCause.CHALLENGE_TIMEOUT, msg.sender);
            _payout(c.challenger, bounty + c.bond); // bounty + bond refund
        } else {
            emit ChallengeRefunded(challengeId);
            _payout(c.challenger, c.bond);
        }
    }

    function _challenge(uint64 challengeId) internal view returns (Challenge storage c) {
        c = challengeRecords[challengeId];
        if (c.challenger == address(0)) revert UnknownChallenge(challengeId);
    }

    // ---------------------------------------------------------------------------
    // Payouts: push with pull fallback. Every ETH payout in the system uses this one
    // pattern; no payout path can revert the operation that triggered it.
    // ---------------------------------------------------------------------------

    /// Push stipend: enough gas for a multisig receive, too little for reentrancy
    /// mischief under checks-effects-interactions ordering.
    uint256 private constant PAYOUT_GAS_STIPEND = 50_000;

    /// Drain the caller's pull-fallback balance. A failing transfer reverts (state
    /// restored) and can be retried later.
    function claim() external {
        uint256 amount = claimable[msg.sender];
        if (amount == 0) revert NothingClaimable();
        claimable[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amount, gas: PAYOUT_GAS_STIPEND}("");
        if (!ok) revert PayoutFailed();
        emit Claimed(msg.sender, amount);
    }

    /// Push `amount` to `to`; on any failure park it in the claimable ledger instead.
    /// Callers MUST finish all state changes first (CEI).
    function _payout(address to, uint256 amount) internal {
        (bool ok,) = to.call{value: amount, gas: PAYOUT_GAS_STIPEND}("");
        if (!ok) {
            claimable[to] += amount;
            emit PayoutDeferred(to, amount);
        }
    }

    // ---------------------------------------------------------------------------
    // Internals.
    // ---------------------------------------------------------------------------

    /// The standard EIP-712 digest: `keccak256(0x1901 ‖ domainSeparator ‖ structHash)`.
    function _digest(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", domainSeparator(), structHash));
    }

    /// The publisher wallet must return the ERC-1271 magic value for the digest. Any
    /// failure — wrong value, revert, malformed return, no code at the wallet — is
    /// BadSignature. Low-level staticcall: a high-level call would revert without data on
    /// a codeless publisher (extcodesize check) instead of reporting the normative error.
    function _requireValidSignature(bytes32 digest, bytes calldata sig) internal view {
        (bool ok, bytes memory ret) =
            publisher.staticcall(abi.encodeCall(IERC1271.isValidSignature, (digest, sig)));
        if (!ok || ret.length < 32 || abi.decode(ret, (bytes32)) != bytes32(ERC1271_MAGIC)) {
            revert BadSignature();
        }
    }

    /// One blob's KZG opening (declaration check 3): the EIP-4844 point-evaluation
    /// precompile with input `vh ‖ z ‖ y ‖ commitment ‖ kzgProof` (192 bytes). A
    /// wrong-length commitment or proof simply yields a non-192-byte input, which the
    /// precompile rejects.
    function _verifyOpening(bytes32 vh, bytes32 z, BlobOpening calldata o, uint256 blobIndex)
        private
        view
    {
        (bool ok,) =
            POINT_EVALUATION.staticcall(abi.encodePacked(vh, z, o.y, o.commitment, o.kzgProof));
        if (!ok) revert PointEvaluationFailed(blobIndex);
    }

    /// The circuit's public-input byte layout is deliberately not yet specified, and
    /// inventing an encoding is forbidden — a silent guess becomes permanent. Until the
    /// spec defines the layout, the instance passes empty publicValues and the mock
    /// verifier validates only (vkey, proof).
    /// TODO(spec): once the layout is written, encode the equivalence statement's public
    /// values exactly as specified. This function body is the only place that changes;
    /// no call site moves.
    function _equivalencePublicValues() private pure returns (bytes memory) {
        return "";
    }

    /// Carrier reimbursement hook (declaration step 6). Milestone 4 deploys the
    /// paymaster in the constructor and wires this up (gas-capped call, failure ignored,
    /// reentrancy-guarded, strictly after all state changes). Until then: no-op.
    function _reimburse(address carrier, uint256 numBlobs, bool isDeclaration) internal {
        // no-op until milestone 4 (paymaster)
    }
}
