//! The BlobsitterInstance ABI surface, transcribed from the contract ONCE for all
//! Rust consumers (the follower here, the testkit harness, later the carrier and
//! publisher CLIs). Two independent transcriptions drifting apart would let each
//! side's tests pass against its own dialect while missing real chain events — so
//! there is exactly one, and the Layer-2 suite exercises it against the real
//! deployed artifact end to end.

use alloy::sol;

sol! {
    #[sol(rpc)]
    #[derive(Debug, PartialEq)]
    contract Blobsitter {
        struct Params {
            address publisher;
            uint256 stakeWei;
            uint64 responseWindow;
            uint64 unbondingDelay;
            uint64 custodyPeriod;
            uint64 lapseGrace;
            uint32 custodyK;
            uint16 maxSample;
            uint16 bountyBps;
            uint256 carrierTipWei;
            uint256 provingSubsidyWei;
            uint256 bucketRateWeiPerDay;
            uint256 bucketCapWei;
            uint64 dormancyWindow;
            uint64 dormancyMinChunks;
        }

        struct Declaration {
            uint64 nonce;
            uint64 deadline;
            bytes32[] blobVersionedHashes;
            bytes32[] newSubtreePeaks;
            uint64 newLeafCount;
            address designatedCarrier;
            bytes32 appPointer;
        }

        struct BlobOpening {
            bytes32 y;
            bytes commitment;
            bytes kzgProof;
        }

        enum ProviderStatus {
            NONE,
            ACTIVE,
            UNBONDING,
            EXITED,
            SLASHED
        }

        enum SlashCause {
            CHALLENGE_TIMEOUT,
            LAPSE
        }

        enum CustodyStatus {
            NONE,
            CURRENT,
            STALE,
            LAPSE_ELIGIBLE,
            LAPSABLE
        }

        struct Provider {
            address operator;
            address withdrawal;
            ProviderStatus status;
            uint64 anchor;
            uint64 lastProvenPlusOne;
            bool lastDegraded;
            uint64 commitPeriodPlusOne;
            bytes32 commitSeed;
            bytes32 commitRoot;
            uint64 commitLeafCount;
            uint64 unbondingAt;
            bytes32 exitRoot;
            uint64 exitLeafCount;
            uint32 openChallenges;
        }

        struct Challenge {
            uint64 providerId;
            address challenger;
            uint256 bond;
            uint64 openedAt;
            bytes32 pinnedRoot;
            uint64 pinnedLeafCount;
            bytes32 indicesHash;
            uint16 k;
            bool resolved;
        }

        /// Challenge-response payload: raw chunk + sibling path, bottom-up.
        struct ChunkProof {
            bytes31 chunk;
            bytes32[] path;
        }

        event Declared(
            uint64 indexed nonce,
            uint64 newLeafCount,
            bytes32[] blobVersionedHashes,
            bytes32[] newSubtreePeaks,
            bytes32 appPointer,
            address carrier
        );
        event Staked(uint64 indexed providerId, address operator, address withdrawal);
        event UnbondingInitiated(uint64 indexed providerId, bytes32 exitRoot, uint64 exitLeafCount);
        event Withdrawn(uint64 indexed providerId);
        event Slashed(uint64 indexed providerId, SlashCause cause, address executor);
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
        event ChallengeTimedOut(uint64 indexed challengeId);
        event CustodyCommitted(
            uint64 indexed providerId, uint64 period, bytes32 seed, bytes32 root, uint64 leafCount
        );
        event CustodyProven(uint64 indexed providerId, uint64 period, bool degraded);

        function declareFor(
            Declaration d,
            bytes publisherSig,
            BlobOpening[] openings,
            bytes equivalenceProof
        ) external;

        function stake(address operator, address withdrawal) external payable returns (uint64);
        function initiateUnbonding(uint64 providerId) external;
        function withdraw(uint64 providerId) external;

        function challenge(uint64 providerId, uint64[] indices) external payable returns (uint64);
        function respond(
            uint64 challengeId,
            uint64[] indices,
            uint64 n,
            bytes32[] pinnedPeaks,
            ChunkProof[] proofs
        ) external;
        function resolveTimeout(uint64 challengeId) external;

        function beginProof(uint64 providerId) external;
        function submitProof(uint64 providerId, bytes proof) external;
        function submitProofEscape(
            uint64 providerId,
            uint64 n,
            bytes32[] pinnedPeaks,
            ChunkProof[] reveals
        ) external;
        function lapse(uint64 providerId) external;

        function leafCount() external view returns (uint64);
        function declarationNonce() external view returns (uint64);
        function allPeaks() external view returns (bytes32[] memory);
        function root() external view returns (bytes32);
        function getProvider(uint64 providerId) external view returns (Provider memory);
        function getChallenge(uint64 challengeId) external view returns (Challenge memory);
        function custodyStatus(uint64 providerId) external view returns (CustodyStatus);
        function custodyPeriodIndex(uint64 providerId) external view returns (uint64);
        function responseWindow() external view returns (uint64);
        function unbondingDelay() external view returns (uint64);
        function custodyPeriod() external view returns (uint64);
        function lapseGrace() external view returns (uint64);
        function maxSample() external view returns (uint16);
        function custodyK() external view returns (uint32);
    }
}
