// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {CrowdVault} from "../src/CrowdVault.sol";
import {CrowdVaultFactory} from "../src/CrowdVaultFactory.sol";

/// Usage:
///   RECIPIENT=0x... THRESHOLD_WEI=10000000000000000000 CLAIM_WINDOW_SECONDS=172800 \
///   KEY_X=0x... KEY_Y=0x... [FACTORY=0x...] \
///   forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast --account deployer --sender 0x...
///
/// KEY_X / KEY_Y come from `vault-seal keygen`. Without FACTORY, a new factory
/// is deployed first; reuse its address for later vaults and in the web page.
/// The deployment forwards 1 wei to the recipient to prove it accepts ETH.
contract Deploy is Script {
    function run() external returns (CrowdVault vault) {
        address payable recipient = payable(vm.envAddress("RECIPIENT"));
        uint256 threshold = vm.envUint("THRESHOLD_WEI");
        uint256 window = vm.envUint("CLAIM_WINDOW_SECONDS");
        uint256 keyX = vm.envUint("KEY_X");
        uint256 keyY = vm.envUint("KEY_Y");
        address existing = vm.envOr("FACTORY", address(0));

        vm.startBroadcast();
        CrowdVaultFactory factory = existing == address(0) ? new CrowdVaultFactory() : CrowdVaultFactory(existing);
        vault = factory.create{value: 1}(recipient, threshold, window, keyX, keyY);
        vm.stopBroadcast();

        console.log("CrowdVaultFactory at", address(factory));
        console.log("CrowdVault deployed at", address(vault));
    }
}
