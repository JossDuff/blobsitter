// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {FixtureKzgTest} from "test/FixtureKzg.t.sol";

/// The fork half of the real-cryptography coverage: the exact fixture suite — real
/// c-kzg opening through declareFor, wrong-y rejection — re-run against a mainnet
/// fork, so the precompile exercised is the forked chain's, not just the local EVM's.
///
/// Secret-gated: skips (visibly) unless ETH_RPC_URL is set. CI passes the repo secret
/// through when configured; locally: `ETH_RPC_URL=<url> forge test --match-path
/// "test/fork/*"`.
contract PointEvalForkTest is FixtureKzgTest {
    function setUp() public override {
        string memory url = vm.envOr("ETH_RPC_URL", string(""));
        if (bytes(url).length == 0) {
            vm.skip(true);
            return;
        }
        vm.createSelectFork(url);
        super.setUp();
    }
}
