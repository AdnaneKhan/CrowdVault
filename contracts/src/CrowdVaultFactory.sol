// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CrowdVault} from "./CrowdVault.sol";

/// @title CrowdVaultFactory
/// @notice Creates vaults and records which addresses are genuine. The vault
///         code is compiled into this factory, so `isVault(a)` means `a` runs
///         exactly the CrowdVault code, not a lookalike. The vault page only
///         shows vaults this factory created.
contract CrowdVaultFactory {
    mapping(address => bool) public isVault;

    event VaultCreated(
        address indexed vault,
        address indexed recipient,
        uint256 threshold,
        uint256 claimWindow,
        uint256 keyX,
        uint256 keyY
    );

    /// @notice Send a small value (1 wei is enough); it is forwarded to the
    ///         recipient to prove the recipient accepts ETH.
    function create(address payable recipient, uint256 threshold, uint256 claimWindow, uint256 keyX, uint256 keyY)
        external
        payable
        returns (CrowdVault vault)
    {
        vault = new CrowdVault{value: msg.value}(recipient, threshold, claimWindow, keyX, keyY);
        isVault[address(vault)] = true;
        emit VaultCreated(address(vault), recipient, threshold, claimWindow, keyX, keyY);
    }
}
