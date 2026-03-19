// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ChannelPayee
/// @notice Minimal per-channel contract that acts as the payee for a
///         PrivacyEscrowZK channel.  Deployed by ChannelPayeeFactory via
///         CREATE2 so the address is deterministic from a one-time merchant
///         key.  Anyone can relay merchant-signed instructions — no
///         privileged operator needed.
///
///         Only two escrow functions require msg.sender == payee:
///           • setMerchantCommitment  (bind merchant identity)
///           • close                  (finalize channel)
///         settle() is permissionless on the escrow, so callers can invoke
///         it directly without going through this contract.
contract ChannelPayee {

    address public immutable escrow;
    address public immutable merchantKey;

    error InvalidMerchantSignature();

    constructor(address _escrow, address _merchantKey) {
        escrow = _escrow;
        merchantKey = _merchantKey;
    }

    /// @notice Relay a setMerchantCommitment call authorized by the merchant.
    function setMerchantCommitment(
        bytes32 channelId,
        bytes32 merchantCommitment,
        bytes calldata merchantSig
    ) external {
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            keccak256(abi.encode(
                "setMerchantCommitment",
                channelId,
                merchantCommitment,
                address(this)
            ))
        ));
        if (_recover(digest, merchantSig) != merchantKey) {
            revert InvalidMerchantSignature();
        }

        (bool ok, ) = escrow.call(abi.encodeWithSignature(
            "setMerchantCommitment(bytes32,bytes32)", channelId, merchantCommitment
        ));
        require(ok);
    }

    /// @notice Relay a close call authorized by the merchant.
    function close(
        bytes32 channelId,
        uint128 cumulativeAmount,
        bytes calldata voucherSignature,
        bytes calldata merchantSig
    ) external {
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            keccak256(abi.encode(
                "close",
                channelId,
                cumulativeAmount,
                address(this)
            ))
        ));
        if (_recover(digest, merchantSig) != merchantKey) {
            revert InvalidMerchantSignature();
        }

        (bool ok, ) = escrow.call(abi.encodeWithSignature(
            "close(bytes32,uint128,bytes)", channelId, cumulativeAmount, voucherSignature
        ));
        require(ok);
    }

    function _recover(
        bytes32 digest,
        bytes calldata sig
    ) internal pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 r = bytes32(sig[0:32]);
        bytes32 s = bytes32(sig[32:64]);
        uint8 v = uint8(sig[64]);
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return address(0);
        }
        return ecrecover(digest, v, r, s);
    }
}
