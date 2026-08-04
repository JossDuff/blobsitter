// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// The paymaster's instance-facing surface. Milestone 4 implements the paymaster
/// (deployed by the instance constructor, bound one-way); until then the instance's
/// reimbursement hook is a documented no-op behind this interface.
///
/// The paymaster is strictly non-load-bearing: its failure is always a no-op for
/// publication, and nothing but reimbursements, dormancy reclaims, and slash
/// absorption can ever move its funds.
interface IPaymaster {
    /// Instance-only. The instance computes `amount` — it alone knows the transaction's
    /// shape: the blob fee at the current blob basefee, the execution gas at the current
    /// basefee, plus the fixed carrier tip (and, for declarations, the proving subsidy).
    /// The paymaster only enforces its refill-rate bucket and pays all-or-nothing.
    function reimburse(address carrier, uint256 amount, bool isDeclaration) external;

    /// Instance-only, payable: slash remainders — absorbed, never ledger-credited.
    function absorbSlash() external payable;
}
