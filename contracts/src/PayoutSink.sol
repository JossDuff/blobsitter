// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// The one ETH-payout pattern every contract in the system uses: push with pull
/// fallback. A push is a call with a fixed 50k gas stipend — enough for a multisig
/// receive, too little for reentrancy mischief under checks-effects-interactions
/// ordering. If the push fails for any reason, the amount is parked in the claimable
/// ledger instead, and the recipient collects later via claim(). No payout path can
/// ever revert the operation that triggered it, and parked balances survive
/// indefinitely (a recipient that can neither receive ETH within the stipend nor call
/// claim() strands its own funds — documented recipient guidance in the spec).
abstract contract PayoutSink {
    error NothingClaimable();
    error PayoutFailed();

    event PayoutDeferred(address indexed recipient, uint256 amount);
    event Claimed(address indexed recipient, uint256 amount);

    uint256 private constant PAYOUT_GAS_STIPEND = 50_000;

    /// Balances a failed push parked here; claim() drains the caller's entry.
    mapping(address => uint256) public claimable;
    /// Sum of all parked balances: ETH that is already spoken for. Anything that
    /// spends from the contract's balance (reimbursement checks, dormancy sweeps)
    /// must treat only balance − totalClaimable as available.
    uint256 public totalClaimable;

    /// Drain the caller's parked balance. A failing transfer reverts (state restored)
    /// and can be retried later.
    function claim() external {
        uint256 amount = claimable[msg.sender];
        if (amount == 0) revert NothingClaimable();
        claimable[msg.sender] = 0;
        totalClaimable -= amount;
        (bool ok,) = msg.sender.call{value: amount, gas: PAYOUT_GAS_STIPEND}("");
        if (!ok) revert PayoutFailed();
        emit Claimed(msg.sender, amount);
    }

    /// Push `amount` to `to`; on any failure park it in the ledger instead.
    /// Callers MUST finish all state changes first (checks-effects-interactions).
    function _payout(address to, uint256 amount) internal {
        (bool ok,) = to.call{value: amount, gas: PAYOUT_GAS_STIPEND}("");
        if (!ok) {
            claimable[to] += amount;
            totalClaimable += amount;
            emit PayoutDeferred(to, amount);
        }
    }
}
