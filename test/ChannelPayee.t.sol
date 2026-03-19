// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {PrivacyEscrowZK} from "../src/PrivacyEscrowZK.sol";
import {Groth16Verifier} from "../src/Groth16Verifier.sol";
import {ChannelPayee} from "../src/ChannelPayee.sol";
import {ChannelPayeeFactory} from "../src/ChannelPayeeFactory.sol";
import {MockERC20} from "./MockERC20.sol";
import {PoseidonT3} from "poseidon-solidity/PoseidonT3.sol";

contract ChannelPayeeTest is Test {
    PrivacyEscrowZK escrow;
    ChannelPayeeFactory factory;
    MockERC20 token;

    address payer;
    uint256 payerKey;

    // Merchant one-time key (fresh per session)
    address merchantOneTimeAddr;
    uint256 merchantOneTimeKey;

    // Merchant secrets for Poseidon commitment
    bytes32 merchantCommitment;

    // EIP-712
    bytes32 constant VOUCHER_TYPEHASH =
        keccak256("Voucher(bytes32 channelId,uint128 cumulativeAmount)");

    function setUp() public {
        (payer, payerKey) = makeAddrAndKey("payer");
        (merchantOneTimeAddr, merchantOneTimeKey) = makeAddrAndKey("merchant-one-time");

        Groth16Verifier verifier = new Groth16Verifier();
        escrow = new PrivacyEscrowZK(verifier);
        factory = new ChannelPayeeFactory(address(escrow));
        token = new MockERC20();

        // Poseidon-based commitment
        merchantCommitment = bytes32(PoseidonT3.hash([uint256(12345), uint256(67890)]));

        token.mint(payer, 100e6);
        vm.prank(payer);
        token.approve(address(escrow), type(uint256).max);
    }

    // ================================================================
    // Helpers
    // ================================================================

    function _signVoucher(
        uint256 signerKey,
        bytes32 channelId,
        uint128 cumulativeAmount
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(abi.encode(VOUCHER_TYPEHASH, channelId, cumulativeAmount));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", escrow.domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signMerchantAction(
        string memory action,
        bytes32 channelId,
        uint128 value,
        address payeeContract
    ) internal view returns (bytes memory) {
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            keccak256(abi.encode(action, channelId, value, payeeContract))
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(merchantOneTimeKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signSetCommitment(
        bytes32 channelId,
        bytes32 commitment,
        address payeeContract
    ) internal view returns (bytes memory) {
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            keccak256(abi.encode("setMerchantCommitment", channelId, commitment, payeeContract))
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(merchantOneTimeKey, digest);
        return abi.encodePacked(r, s, v);
    }

    // ================================================================
    // Tests — Factory
    // ================================================================

    function test_factory_deterministic_address() public {
        address predicted = factory.computePayeeAddress(merchantOneTimeAddr);
        address deployed = factory.deploy(merchantOneTimeAddr);
        assertEq(predicted, deployed);
    }

    function test_factory_deploys_correct_params() public {
        address deployed = factory.deploy(merchantOneTimeAddr);
        ChannelPayee cp = ChannelPayee(deployed);
        assertEq(cp.escrow(), address(escrow));
        assertEq(cp.merchantKey(), merchantOneTimeAddr);
    }

    // ================================================================
    // Tests — End-to-end: no trusted operator
    // ================================================================

    function test_full_flow_no_operator() public {
        // 1. Merchant generates one-time key, factory computes payee address
        address payeeAddr = factory.computePayeeAddress(merchantOneTimeAddr);

        // 2. Client opens channel to the predicted address (standard open)
        vm.prank(payer);
        bytes32 channelId = escrow.open(
            payeeAddr, address(token), 10e6, bytes32(uint256(1)), address(0)
        );

        // 3. Deploy the ChannelPayee contract (anyone can do this)
        address relayer = makeAddr("relayer");
        vm.prank(relayer);
        factory.deploy(merchantOneTimeAddr);

        // 4. Merchant signs setMerchantCommitment, relayer submits
        bytes memory commitSig = _signSetCommitment(channelId, merchantCommitment, payeeAddr);
        vm.prank(relayer);
        ChannelPayee(payeeAddr).setMerchantCommitment(channelId, merchantCommitment, commitSig);

        // Verify commitment was set
        PrivacyEscrowZK.Channel memory ch = escrow.getChannel(channelId);
        assertEq(ch.merchantCommitment, merchantCommitment);

        // 5. Settle — permissionless, anyone can call directly
        bytes memory voucherSig = _signVoucher(payerKey, channelId, 2e6);
        vm.prank(relayer);
        escrow.settle(channelId, 2e6, voucherSig);

        ch = escrow.getChannel(channelId);
        assertEq(ch.settled, 2e6);
        assertEq(escrow.noteCount(), 1);

        // 6. Merchant signs close, relayer submits
        bytes memory closeMerchantSig = _signMerchantAction("close", channelId, 2e6, payeeAddr);
        vm.prank(relayer);
        ChannelPayee(payeeAddr).close(channelId, 2e6, voucherSig, closeMerchantSig);

        // Verify channel closed, payer refunded
        ch = escrow.getChannel(channelId);
        assertTrue(ch.finalized);
        assertEq(token.balanceOf(payer), 98e6); // 100 - 10 deposit + 8 refund
    }

    function test_wrong_merchant_sig_rejected() public {
        address payeeAddr = factory.deploy(merchantOneTimeAddr);

        vm.prank(payer);
        bytes32 channelId = escrow.open(
            payeeAddr, address(token), 10e6, bytes32(uint256(2)), address(0)
        );

        // Sign with wrong key
        (, uint256 wrongKey) = makeAddrAndKey("wrong-key");
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            keccak256(abi.encode("setMerchantCommitment", channelId, merchantCommitment, payeeAddr))
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongKey, digest);
        bytes memory badSig = abi.encodePacked(r, s, v);

        vm.expectRevert(ChannelPayee.InvalidMerchantSignature.selector);
        ChannelPayee(payeeAddr).setMerchantCommitment(channelId, merchantCommitment, badSig);
    }

    function test_two_merchants_independent_payees() public {
        // Merchant A
        (address keyA, uint256 privA) = makeAddrAndKey("merchant-A-session");
        address payeeA = factory.deploy(keyA);

        // Merchant B
        (address keyB, uint256 privB) = makeAddrAndKey("merchant-B-session");
        address payeeB = factory.deploy(keyB);

        // Both are unique addresses
        assertTrue(payeeA != payeeB);

        // Open channels to each
        vm.prank(payer);
        bytes32 chA = escrow.open(payeeA, address(token), 5e6, bytes32(uint256(10)), address(0));

        token.mint(payer, 5e6);
        vm.prank(payer);
        token.approve(address(escrow), type(uint256).max);
        vm.prank(payer);
        bytes32 chB = escrow.open(payeeB, address(token), 5e6, bytes32(uint256(11)), address(0));

        // Each merchant sets their own Poseidon commitment via their own payee contract
        bytes32 commitA = bytes32(PoseidonT3.hash([uint256(111), uint256(222)]));
        bytes32 commitB = bytes32(PoseidonT3.hash([uint256(333), uint256(444)]));

        bytes32 digestA = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            keccak256(abi.encode("setMerchantCommitment", chA, commitA, payeeA))
        ));
        (uint8 vA, bytes32 rA, bytes32 sA) = vm.sign(privA, digestA);
        ChannelPayee(payeeA).setMerchantCommitment(chA, commitA, abi.encodePacked(rA, sA, vA));

        bytes32 digestB = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            keccak256(abi.encode("setMerchantCommitment", chB, commitB, payeeB))
        ));
        (uint8 vB, bytes32 rB, bytes32 sB) = vm.sign(privB, digestB);
        ChannelPayee(payeeB).setMerchantCommitment(chB, commitB, abi.encodePacked(rB, sB, vB));

        // Both commitments set independently, no shared operator
        assertEq(escrow.getChannel(chA).merchantCommitment, commitA);
        assertEq(escrow.getChannel(chB).merchantCommitment, commitB);
    }
}
