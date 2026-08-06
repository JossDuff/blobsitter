//! The BlobsitterInstance ABI surface, transcribed from the contract ONCE for all
//! Rust consumers (the follower here, the testkit harness, later the carrier and
//! publisher CLIs). Two independent transcriptions drifting apart would let each
//! side's tests pass against its own dialect while missing real chain events — so
//! there is exactly one, and the Layer-2 suite exercises it against the real
//! deployed artifact end to end.

use alloy::sol;

sol! {
    #[sol(rpc)]
    #[derive(Debug)]
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

        event Declared(
            uint64 indexed nonce,
            uint64 newLeafCount,
            bytes32[] blobVersionedHashes,
            bytes32[] newSubtreePeaks,
            bytes32 appPointer,
            address carrier
        );

        function declareFor(
            Declaration d,
            bytes publisherSig,
            BlobOpening[] openings,
            bytes equivalenceProof
        ) external;

        function leafCount() external view returns (uint64);
        function declarationNonce() external view returns (uint64);
        function allPeaks() external view returns (bytes32[] memory);
        function root() external view returns (bytes32);
    }
}
