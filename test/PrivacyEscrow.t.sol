// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {PrivacyEscrow} from "../src/PrivacyEscrow.sol";
import {MockERC20} from "./MockERC20.sol";

contract PrivacyEscrowTest is Test {
    PrivacyEscrow escrow;
    MockERC20 token;

    // Actors
    address payer;
    uint256 payerKey;
    address payee; // shared server/operator
    address merchant1;
    address merchant2;

    // Merchant secrets
    bytes32 merchant1PubKey = keccak256("merchant1-pubkey");
    bytes32 merchant1Blinding = keccak256("merchant1-blinding");
    bytes32 merchant1Commitment;

    bytes32 merchant2PubKey = keccak256("merchant2-pubkey");
    bytes32 merchant2Blinding = keccak256("merchant2-blinding");
    bytes32 merchant2Commitment;

    // EIP-712
    bytes32 constant VOUCHER_TYPEHASH =
        keccak256("Voucher(bytes32 channelId,uint128 cumulativeAmount)");
    bytes32 constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    function setUp() public {
        (payer, payerKey) = makeAddrAndKey("payer");
        payee = makeAddr("payee");
        merchant1 = makeAddr("merchant1");
        merchant2 = makeAddr("merchant2");

        escrow = new PrivacyEscrow();
        token = new MockERC20();

        merchant1Commitment = keccak256(abi.encode(merchant1PubKey, merchant1Blinding));
        merchant2Commitment = keccak256(abi.encode(merchant2PubKey, merchant2Blinding));

        // Fund payer
        token.mint(payer, 100e6);
        vm.prank(payer);
        token.approve(address(escrow), type(uint256).max);
    }

    // ================================================================
    // Helpers
    // ================================================================

    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encode(
            EIP712_DOMAIN_TYPEHASH,
            keccak256("Tempo Stream Channel"),
            keccak256("1"),
            block.chainid,
            address(escrow)
        ));
    }

    function _signVoucher(
        uint256 signerKey,
        bytes32 channelId,
        uint128 cumulativeAmount
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(abi.encode(VOUCHER_TYPEHASH, channelId, cumulativeAmount));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _openChannel(
        bytes32 merchantCommitment,
        uint128 deposit,
        bytes32 salt
    ) internal returns (bytes32 channelId) {
        vm.prank(payer);
        channelId = escrow.open(
            payee,
            address(token),
            deposit,
            salt,
            address(0), // payer signs
            merchantCommitment
        );
    }

    /// @dev Build a Merkle proof for `leafIndex` against an incremental
    ///      tree with `totalLeaves` leaves and the given inserted leaves.
    ///      Mirrors the contract's incremental tree logic.
    function _buildMerkleProof(
        bytes32[] memory leaves,
        uint256 leafIndex
    ) internal view returns (bytes32[] memory proof) {
        uint256 depth = 20;
        proof = new bytes32[](depth);

        // Build full tree layer by layer
        uint256 n = leaves.length;
        // Extend to full width at level 0 with zeros
        bytes32[] memory layer = new bytes32[](1 << depth);

        // Zero leaf at level 0
        bytes32 zeroLeaf = keccak256(abi.encodePacked(bytes32(0)));

        for (uint256 i = 0; i < (1 << depth); i++) {
            layer[i] = (i < n) ? leaves[i] : zeroLeaf;
        }

        // We need to use the same zero values the contract uses.
        // zeros[0] = keccak256(abi.encodePacked(bytes32(0)))
        // But the contract stores leaves directly (not hashed), and the
        // zero hashes are the *node* zeros.
        //
        // Actually, the contract inserts `leaf` directly as the node at
        // level 0.  The zero for level 0 is `keccak256(abi.encodePacked(bytes32(0)))`.
        // But we already set empty slots to that value above.
        //
        // We just need to recompute each level correctly.
        // The contract uses keccak256(abi.encodePacked(left, right)).

        uint256 idx = leafIndex;

        for (uint256 d = 0; d < depth; d++) {
            // Sibling index
            uint256 sibIdx = idx ^ 1;
            proof[d] = layer[sibIdx];

            // Compute next layer
            uint256 nextLen = layer.length / 2;
            bytes32[] memory next = new bytes32[](nextLen);
            for (uint256 j = 0; j < nextLen; j++) {
                next[j] = keccak256(abi.encodePacked(layer[2 * j], layer[2 * j + 1]));
            }
            layer = next;
            idx >>= 1;
        }
    }

    // ================================================================
    // Tests — Channel lifecycle
    // ================================================================

    function test_open_channel() public {
        bytes32 channelId = _openChannel(merchant1Commitment, 10e6, bytes32(uint256(1)));

        PrivacyEscrow.Channel memory ch = escrow.getChannel(channelId);
        assertEq(ch.payer, payer);
        assertEq(ch.payee, payee);
        assertEq(ch.token, address(token));
        assertEq(ch.deposit, 10e6);
        assertEq(ch.settled, 0);
        assertEq(ch.merchantCommitment, merchant1Commitment);
        assertFalse(ch.finalized);
    }

    function test_open_rejects_zero_commitment() public {
        vm.prank(payer);
        vm.expectRevert(PrivacyEscrow.InvalidMerchantCommitment.selector);
        escrow.open(payee, address(token), 10e6, bytes32(0), address(0), bytes32(0));
    }

    function test_topUp() public {
        bytes32 channelId = _openChannel(merchant1Commitment, 5e6, bytes32(uint256(2)));

        token.mint(payer, 5e6);
        vm.prank(payer);
        escrow.topUp(channelId, 5e6);

        PrivacyEscrow.Channel memory ch = escrow.getChannel(channelId);
        assertEq(ch.deposit, 10e6);
    }

    function test_settle_mints_note() public {
        bytes32 channelId = _openChannel(merchant1Commitment, 10e6, bytes32(uint256(3)));

        uint256 notesBefore = escrow.noteCount();
        bytes32 rootBefore = escrow.getMerkleRoot();

        bytes memory sig = _signVoucher(payerKey, channelId, 1e6);

        vm.prank(payee);
        escrow.settle(channelId, 1e6, sig);

        assertEq(escrow.noteCount(), notesBefore + 1);
        // Root must change after insert
        assertTrue(escrow.getMerkleRoot() != rootBefore);
        // Old root still valid
        assertTrue(escrow.knownRoots(rootBefore));

        PrivacyEscrow.Channel memory ch = escrow.getChannel(channelId);
        assertEq(ch.settled, 1e6);
        // Funds stay in contract (not sent to payee directly)
        assertEq(token.balanceOf(address(escrow)), 10e6);
    }

    function test_settle_multiple_vouchers() public {
        bytes32 channelId = _openChannel(merchant1Commitment, 10e6, bytes32(uint256(4)));

        // Settle 1
        vm.prank(payee);
        escrow.settle(channelId, 1e6, _signVoucher(payerKey, channelId, 1e6));

        // Settle 2
        vm.prank(payee);
        escrow.settle(channelId, 3e6, _signVoucher(payerKey, channelId, 3e6));

        assertEq(escrow.noteCount(), 2);
        PrivacyEscrow.Channel memory ch = escrow.getChannel(channelId);
        assertEq(ch.settled, 3e6);
    }

    function test_settle_rejects_non_monotonic() public {
        bytes32 channelId = _openChannel(merchant1Commitment, 10e6, bytes32(uint256(5)));

        vm.prank(payee);
        escrow.settle(channelId, 5e6, _signVoucher(payerKey, channelId, 5e6));

        vm.prank(payee);
        vm.expectRevert(PrivacyEscrow.AmountNotIncreasing.selector);
        escrow.settle(channelId, 3e6, _signVoucher(payerKey, channelId, 3e6));
    }

    function test_settle_rejects_exceeds_deposit() public {
        bytes32 channelId = _openChannel(merchant1Commitment, 10e6, bytes32(uint256(6)));

        vm.prank(payee);
        vm.expectRevert(PrivacyEscrow.AmountExceedsDeposit.selector);
        escrow.settle(channelId, 20e6, _signVoucher(payerKey, channelId, 20e6));
    }

    function test_close_mints_final_note_and_refunds() public {
        bytes32 channelId = _openChannel(merchant1Commitment, 10e6, bytes32(uint256(7)));

        // Settle half
        vm.prank(payee);
        escrow.settle(channelId, 5e6, _signVoucher(payerKey, channelId, 5e6));

        uint256 payerBefore = token.balanceOf(payer);

        // Close with final voucher at 7e6
        vm.prank(payee);
        escrow.close(channelId, 7e6, _signVoucher(payerKey, channelId, 7e6));

        // 2 notes total: settle(5e6) + close delta(2e6)
        assertEq(escrow.noteCount(), 2);

        // Payer gets refund of 3e6
        assertEq(token.balanceOf(payer), payerBefore + 3e6);

        // Channel finalized
        PrivacyEscrow.Channel memory ch = escrow.getChannel(channelId);
        assertTrue(ch.finalized);
    }

    function test_requestClose_and_withdraw() public {
        bytes32 channelId = _openChannel(merchant1Commitment, 10e6, bytes32(uint256(8)));

        vm.prank(payer);
        escrow.requestClose(channelId);

        // Cannot withdraw before grace period
        vm.prank(payer);
        vm.expectRevert(PrivacyEscrow.CloseNotReady.selector);
        escrow.withdraw(channelId);

        // Warp past grace period
        vm.warp(block.timestamp + 15 minutes + 1);

        uint256 payerBefore = token.balanceOf(payer);
        vm.prank(payer);
        escrow.withdraw(channelId);

        assertEq(token.balanceOf(payer), payerBefore + 10e6);

        PrivacyEscrow.Channel memory ch = escrow.getChannel(channelId);
        assertTrue(ch.finalized);
    }

    // ================================================================
    // Tests — Note redemption (end-to-end)
    // ================================================================

    function test_redeem_single_note() public {
        bytes32 salt = bytes32(uint256(9));
        bytes32 channelId = _openChannel(merchant1Commitment, 10e6, salt);

        // Settle 2 USDC
        vm.prank(payee);
        escrow.settle(channelId, 2e6, _signVoucher(payerKey, channelId, 2e6));

        // The note was the first leaf (index 0).
        // Re-derive the note randomness + commitment identically to contract
        bytes32 noteRandomness = keccak256(abi.encode(
            channelId, uint128(2e6), uint256(1), uint256(0) // block.timestamp=1, noteCount was 0
        ));
        bytes32 noteCommitment = keccak256(abi.encode(
            address(token), uint128(2e6), merchant1Commitment, channelId, noteRandomness
        ));
        bytes32 nullifier = keccak256(abi.encode(noteCommitment, merchant1PubKey));

        // Build Merkle proof for leaf 0 with 1 leaf inserted
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = noteCommitment;
        bytes32[] memory proof = _buildMerkleProof(leaves, 0);

        // Redeem to merchant1's fresh address
        address freshAddr = makeAddr("merchant1-fresh");
        escrow.redeemNote(
            noteCommitment,
            nullifier,
            freshAddr,
            address(token),
            2e6,
            merchant1PubKey,
            merchant1Blinding,
            noteRandomness,
            channelId,
            0,
            proof
        );

        assertEq(token.balanceOf(freshAddr), 2e6);
        assertTrue(escrow.spentNullifiers(nullifier));
    }

    function test_redeem_rejects_double_spend() public {
        bytes32 channelId = _openChannel(merchant1Commitment, 10e6, bytes32(uint256(10)));

        vm.prank(payee);
        escrow.settle(channelId, 1e6, _signVoucher(payerKey, channelId, 1e6));

        bytes32 noteRandomness = keccak256(abi.encode(
            channelId, uint128(1e6), uint256(1), uint256(0)
        ));
        bytes32 noteCommitment = keccak256(abi.encode(
            address(token), uint128(1e6), merchant1Commitment, channelId, noteRandomness
        ));
        bytes32 nullifier = keccak256(abi.encode(noteCommitment, merchant1PubKey));

        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = noteCommitment;
        bytes32[] memory proof = _buildMerkleProof(leaves, 0);

        address freshAddr = makeAddr("fresh");
        escrow.redeemNote(
            noteCommitment, nullifier, freshAddr, address(token), 1e6,
            merchant1PubKey, merchant1Blinding, noteRandomness, channelId, 0, proof
        );

        // Double spend
        vm.expectRevert(PrivacyEscrow.NullifierAlreadySpent.selector);
        escrow.redeemNote(
            noteCommitment, nullifier, freshAddr, address(token), 1e6,
            merchant1PubKey, merchant1Blinding, noteRandomness, channelId, 0, proof
        );
    }

    function test_redeem_rejects_wrong_preimage() public {
        bytes32 channelId = _openChannel(merchant1Commitment, 10e6, bytes32(uint256(11)));

        vm.prank(payee);
        escrow.settle(channelId, 1e6, _signVoucher(payerKey, channelId, 1e6));

        bytes32 noteRandomness = keccak256(abi.encode(
            channelId, uint128(1e6), uint256(1), uint256(0)
        ));
        bytes32 noteCommitment = keccak256(abi.encode(
            address(token), uint128(1e6), merchant1Commitment, channelId, noteRandomness
        ));
        bytes32 nullifier = keccak256(abi.encode(noteCommitment, merchant1PubKey));

        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = noteCommitment;
        bytes32[] memory proof = _buildMerkleProof(leaves, 0);

        // Try with wrong amount
        vm.expectRevert(PrivacyEscrow.InvalidNotePreimage.selector);
        escrow.redeemNote(
            noteCommitment, nullifier, makeAddr("x"), address(token), 2e6,
            merchant1PubKey, merchant1Blinding, noteRandomness, channelId, 0, proof
        );
    }

    // ================================================================
    // Tests — Multi-merchant shared escrow
    // ================================================================

    function test_two_merchants_same_escrow() public {
        // Two channels to same payee (server), different merchant commitments
        bytes32 ch1 = _openChannel(merchant1Commitment, 10e6, bytes32(uint256(20)));

        token.mint(payer, 10e6);
        vm.prank(payer);
        token.approve(address(escrow), type(uint256).max);
        bytes32 ch2 = _openChannel(merchant2Commitment, 10e6, bytes32(uint256(21)));

        // Settle both
        vm.prank(payee);
        escrow.settle(ch1, 3e6, _signVoucher(payerKey, ch1, 3e6));

        vm.prank(payee);
        escrow.settle(ch2, 5e6, _signVoucher(payerKey, ch2, 5e6));

        assertEq(escrow.noteCount(), 2);

        // On-chain: two settlements to same escrow, can't tell which merchant
        // Merchant 1 redeems note 0
        bytes32 nr1 = keccak256(abi.encode(ch1, uint128(3e6), uint256(1), uint256(0)));
        bytes32 nc1 = keccak256(abi.encode(
            address(token), uint128(3e6), merchant1Commitment, ch1, nr1
        ));

        // Merchant 2 redeems note 1
        bytes32 nr2 = keccak256(abi.encode(ch2, uint128(5e6), uint256(1), uint256(1)));
        bytes32 nc2 = keccak256(abi.encode(
            address(token), uint128(5e6), merchant2Commitment, ch2, nr2
        ));

        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = nc1;
        leaves[1] = nc2;

        // Redeem merchant 1
        {
            bytes32[] memory proof1 = _buildMerkleProof(leaves, 0);
            bytes32 null1 = keccak256(abi.encode(nc1, merchant1PubKey));
            address m1Addr = makeAddr("m1-fresh");
            escrow.redeemNote(
                nc1, null1, m1Addr, address(token), 3e6,
                merchant1PubKey, merchant1Blinding, nr1, ch1, 0, proof1
            );
            assertEq(token.balanceOf(m1Addr), 3e6);
        }

        // Redeem merchant 2
        {
            bytes32[] memory proof2 = _buildMerkleProof(leaves, 1);
            bytes32 null2 = keccak256(abi.encode(nc2, merchant2PubKey));
            address m2Addr = makeAddr("m2-fresh");
            escrow.redeemNote(
                nc2, null2, m2Addr, address(token), 5e6,
                merchant2PubKey, merchant2Blinding, nr2, ch2, 1, proof2
            );
            assertEq(token.balanceOf(m2Addr), 5e6);
        }
    }

    // ================================================================
    // Tests — EIP-712 domain matches standard escrow
    // ================================================================

    function test_domain_separator_matches() public view {
        bytes32 expected = _domainSeparator();
        assertEq(escrow.domainSeparator(), expected);
    }

    function test_voucher_digest_matches() public {
        bytes32 channelId = _openChannel(merchant1Commitment, 10e6, bytes32(uint256(30)));
        uint128 amount = 1e6;

        bytes32 structHash = keccak256(abi.encode(VOUCHER_TYPEHASH, channelId, amount));
        bytes32 expected = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));

        assertEq(escrow.getVoucherDigest(channelId, amount), expected);
    }

    // ================================================================
    // Tests — Access control
    // ================================================================

    function test_settle_only_payee() public {
        bytes32 channelId = _openChannel(merchant1Commitment, 10e6, bytes32(uint256(40)));
        bytes memory sig = _signVoucher(payerKey, channelId, 1e6);

        vm.prank(payer);
        vm.expectRevert(PrivacyEscrow.NotPayee.selector);
        escrow.settle(channelId, 1e6, sig);
    }

    function test_topUp_only_payer() public {
        bytes32 channelId = _openChannel(merchant1Commitment, 10e6, bytes32(uint256(41)));

        vm.prank(payee);
        vm.expectRevert(PrivacyEscrow.NotPayer.selector);
        escrow.topUp(channelId, 1e6);
    }

    function test_requestClose_only_payer() public {
        bytes32 channelId = _openChannel(merchant1Commitment, 10e6, bytes32(uint256(42)));

        vm.prank(payee);
        vm.expectRevert(PrivacyEscrow.NotPayer.selector);
        escrow.requestClose(channelId);
    }

    function test_close_only_payee() public {
        bytes32 channelId = _openChannel(merchant1Commitment, 10e6, bytes32(uint256(43)));

        vm.prank(payer);
        vm.expectRevert(PrivacyEscrow.NotPayee.selector);
        escrow.close(channelId, 0, "");
    }

    // ================================================================
    // Tests — Authorized signer delegation
    // ================================================================

    function test_authorized_signer() public {
        (address signer, uint256 signerKey) = makeAddrAndKey("delegated-signer");

        vm.prank(payer);
        bytes32 channelId = escrow.open(
            payee, address(token), 10e6, bytes32(uint256(50)),
            signer, merchant1Commitment
        );

        // Sign with delegated key
        bytes memory sig = _signVoucher(signerKey, channelId, 2e6);
        vm.prank(payee);
        escrow.settle(channelId, 2e6, sig);

        PrivacyEscrow.Channel memory ch = escrow.getChannel(channelId);
        assertEq(ch.settled, 2e6);
    }

    function test_wrong_signer_rejected() public {
        bytes32 channelId = _openChannel(merchant1Commitment, 10e6, bytes32(uint256(51)));

        (, uint256 wrongKey) = makeAddrAndKey("wrong-signer");
        bytes memory sig = _signVoucher(wrongKey, channelId, 1e6);

        vm.prank(payee);
        vm.expectRevert(PrivacyEscrow.InvalidSignature.selector);
        escrow.settle(channelId, 1e6, sig);
    }
}
