// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ChannelPayee} from "./ChannelPayee.sol";

/// @title ChannelPayeeFactory
/// @notice Deploys ChannelPayee contracts via CREATE2 so addresses are
///         deterministic from a one-time merchant key.
///
///         Flow:
///           1. Merchant generates a fresh keypair for a session.
///           2. Anyone calls computePayeeAddress(merchantKey) to get the
///              deterministic payee address.
///           3. Client opens a channel to that address (standard open()).
///           4. Anyone calls deploy(merchantKey) to deploy the contract
///              (can be deferred until first use).
///           5. Relayers forward merchant-signed instructions to the
///              ChannelPayee contract.
contract ChannelPayeeFactory {

    address public immutable escrow;

    event PayeeDeployed(address indexed merchantKey, address payee);

    error AlreadyDeployed();

    constructor(address _escrow) {
        escrow = _escrow;
    }

    /// @notice Compute the deterministic address for a merchant's payee
    ///         contract before deployment.
    function computePayeeAddress(address merchantKey) public view returns (address) {
        bytes32 salt = bytes32(uint256(uint160(merchantKey)));
        bytes32 hash = keccak256(abi.encodePacked(
            bytes1(0xff),
            address(this),
            salt,
            keccak256(abi.encodePacked(
                type(ChannelPayee).creationCode,
                abi.encode(escrow, merchantKey)
            ))
        ));
        return address(uint160(uint256(hash)));
    }

    /// @notice Deploy a ChannelPayee for a merchant's one-time key.
    ///         Anyone can call this — no special permissions needed.
    function deploy(address merchantKey) external returns (address payee) {
        bytes32 salt = bytes32(uint256(uint160(merchantKey)));
        payee = address(new ChannelPayee{salt: salt}(escrow, merchantKey));
        emit PayeeDeployed(merchantKey, payee);
    }
}
