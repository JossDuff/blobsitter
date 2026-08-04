// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {PayoutSink} from "./PayoutSink.sol";

/// The slice of the instance the paymaster reads at reclaim time.
interface IInstanceActivity {
    function activityCheckpointTime() external view returns (uint64);
}

/// The instance's funding sidecar, deployed by the instance constructor and bound to it
/// one-way. Strictly non-load-bearing: it can only (a) reimburse carriers when the
/// instance asks, (b) return funds to donors once the dataset has gone dormant, and
/// (c) absorb slash remainders. It can never touch roots, stakes, challenges, or
/// custody, and its failure — including an empty balance — is always a no-op for
/// publication.
///
/// Reimbursements are throttled by a token bucket: a spending allowance that refills
/// continuously (0.05 ETH/day as sized) up to a fixed cap (1.5 ETH), starting FULL at
/// deployment. The bucket bounds how fast funds can drain — even a worst-case bug or
/// key compromise leaks at most cap + rate x time — while donations themselves are
/// unlimited.
contract BlobsitterPaymaster is PayoutSink {
    error OnlyInstance();
    error NotDormant(uint64 dormantAt);
    error NothingToReclaim();

    event Donated(address indexed donor, uint256 amount);
    event Reimbursed(address indexed carrier, uint256 amount, bool isDeclaration);
    /// The all-or-nothing rule's shortfall record: the request exceeded the bucket
    /// level or the available balance, so nothing was paid.
    event ReimbursementSkipped(
        address indexed carrier, uint256 amount, uint256 bucketLevel, uint256 available
    );
    event SlashAbsorbed(uint256 amount);
    event Reclaimed(address indexed donor, uint256 amount);

    address public immutable instance;
    uint256 public immutable bucketRateWeiPerDay;
    uint256 public immutable bucketCapWei;
    uint64 public immutable dormancyWindow;

    /// The donation ledger: who can reclaim how much weight on dormancy. Slash
    /// remainders and forced ETH are deliberately NOT credited here — no one can
    /// reclaim them individually; the pro-rata sweep covers them.
    mapping(address => uint256) public contributions;
    /// Invariant: the sum of all contributions.
    uint256 public outstanding;

    uint256 internal storedBucketLevel; // as of lastBucketUpdate
    uint64 internal lastBucketUpdate;

    /// Deployed mid-constructor by the instance, whose immutables aren't externally
    /// readable yet — so the sizing arrives as arguments.
    constructor(uint256 ratePerDay, uint256 cap, uint64 dormancyWindow_) {
        instance = msg.sender;
        bucketRateWeiPerDay = ratePerDay;
        bucketCapWei = cap;
        dormancyWindow = dormancyWindow_;
        storedBucketLevel = cap; // the limiter bounds drain rate, not launch readiness
        lastBucketUpdate = uint64(block.timestamp);
    }

    /// Plain transfers and explicit donations both credit the ledger. Irrevocable
    /// except through the dormancy sweep.
    receive() external payable {
        _donate();
    }

    function donate() external payable {
        _donate();
    }

    /// The current spending allowance: continuous refill since the last draw, clamped
    /// to the cap. Multiply-before-divide keeps sub-day refills precise.
    function bucketLevel() public view returns (uint256) {
        uint256 refilled = storedBucketLevel
            + (bucketRateWeiPerDay * (block.timestamp - lastBucketUpdate)) / 1 days;
        return refilled > bucketCapWei ? bucketCapWei : refilled;
    }

    /// ETH not already spoken for by parked payouts.
    function availableBalance() public view returns (uint256) {
        return address(this).balance - totalClaimable;
    }

    /// Pay a carrier the instance-computed amount, all-or-nothing: if either the
    /// bucket or the unencumbered balance can't cover the FULL amount, nothing is paid
    /// and the shortfall is recorded — never a revert, so carriers can simulate
    /// solvency and a broke paymaster never blocks publication. Only the instance may
    /// call; it alone knows the transaction's shape.
    function reimburse(address carrier, uint256 amount, bool isDeclaration) external {
        if (msg.sender != instance) revert OnlyInstance();
        uint256 level = bucketLevel();
        lastBucketUpdate = uint64(block.timestamp);
        if (amount > level || amount > availableBalance()) {
            storedBucketLevel = level;
            emit ReimbursementSkipped(carrier, amount, level, availableBalance());
            return;
        }
        storedBucketLevel = level - amount;
        emit Reimbursed(carrier, amount, isDeclaration);
        _payout(carrier, amount);
    }

    /// Slash remainders: absorbed into the balance, never ledger-credited. On
    /// dormancy the donors' pro-rata sweep covers them.
    function absorbSlash() external payable {
        if (msg.sender != instance) revert OnlyInstance();
        emit SlashAbsorbed(msg.value);
    }

    /// Return a donor's pro-rata share once the dataset has gone dormant (no
    /// checkpoint-advancing declaration for a full dormancy window). Each reclaimer
    /// takes their share of the balance REMAINING at their call; the arithmetic
    /// telescopes so that if every donor reclaims, the entire unencumbered balance —
    /// slash remainders and forced ETH included — is returned. Reclaim does not close
    /// the paymaster: later donations recredit the ledger, and a later declaration
    /// closes the gate again.
    function reclaim() external {
        uint64 t0 = IInstanceActivity(instance).activityCheckpointTime();
        uint64 dormantAt = t0 + dormancyWindow;
        if (block.timestamp <= dormantAt) revert NotDormant(dormantAt);
        uint256 weight = contributions[msg.sender];
        if (weight == 0) revert NothingToReclaim();
        uint256 amount = (availableBalance() * weight) / outstanding;
        outstanding -= weight;
        contributions[msg.sender] = 0;
        emit Reclaimed(msg.sender, amount);
        _payout(msg.sender, amount);
    }

    function _donate() private {
        contributions[msg.sender] += msg.value;
        outstanding += msg.value;
        emit Donated(msg.sender, msg.value);
    }
}
