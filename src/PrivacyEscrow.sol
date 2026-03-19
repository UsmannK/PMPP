// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPrivacyEscrow} from "./interfaces/IPrivacyEscrow.sol";
import {IERC20} from "./interfaces/IERC20.sol";

/// @title PrivacyEscrow
/// @notice MPP-compatible tempo.session escrow that converts settlement
///         deltas into Merkle-tree note commitments for merchant privacy.
///
/// Architecture
/// ────────────
///   1.  Server returns `methodDetails.escrowContract = address(this)`
///       in normal tempo/session 402 challenges.
///   2.  Channel open binds a hidden `merchantCommitment`.
///   3.  Each `settle()` computes delta from cumulative vouchers and
///       immediately appends a note commitment to an append-only
///       incremental Merkle tree (Option A — fully trustless).
///   4.  Merchants redeem notes privately using preimage proofs,
///       membership proofs, and nullifiers.
///
/// Compatibility
/// ─────────────
///   • open / topUp / settle / close / requestClose / withdraw
///     follow standard TempoStreamChannel semantics.
///   • EIP-712 voucher format is identical to the reference escrow:
///         Voucher(bytes32 channelId, uint128 cumulativeAmount)
///         domain = ("Tempo Stream Channel", "1", chainId, address(this))
///   • Clients sign the same vouchers as the vanilla escrow.
///   • The privacy logic is entirely on the settlement / redemption path.
///
/// Note format
/// ───────────
///   commitment = keccak256(abi.encode(
///       asset, amount, merchantCommitment, channelId, noteRandomness
///   ))
///   nullifier  = keccak256(abi.encode(noteCommitment, merchantPubKey))
///
/// Merkle tree
/// ───────────
///   Sparse, append-only, depth-20 (1 048 576 leaves).
///   Updated incrementally — O(depth) hashes per insert.
contract PrivacyEscrow is IPrivacyEscrow {

    // ================================================================
    // Constants
    // ================================================================

    uint64 public constant CLOSE_GRACE_PERIOD = 15 minutes;

    bytes32 public constant VOUCHER_TYPEHASH =
        keccak256("Voucher(bytes32 channelId,uint128 cumulativeAmount)");

    /// @dev Merkle tree depth.  2^20 = 1 048 576 leaves.
    uint256 internal constant TREE_DEPTH = 20;
    uint256 internal constant MAX_LEAVES = 1 << TREE_DEPTH;

    // ================================================================
    // EIP-712 domain (matches TempoStreamChannel exactly)
    // ================================================================

    bytes32 private constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    bytes32 private constant DOMAIN_NAME_HASH = keccak256("Tempo Stream Channel");
    bytes32 private constant DOMAIN_VERSION_HASH = keccak256("1");

    bytes32 private immutable _DOMAIN_SEPARATOR;

    // ================================================================
    // State — channels
    // ================================================================

    mapping(bytes32 => Channel) public channels;

    // ================================================================
    // State — Merkle note tree
    // ================================================================

    /// @dev Number of leaves inserted so far.
    uint256 public noteCount;

    /// @dev filledSubtrees[i] = root of the full subtree of depth i at
    ///      the "left frontier".  Updated on each insert.
    bytes32[TREE_DEPTH] internal _filledSubtrees;

    /// @dev Pre-computed zero hashes.  zeros[0] = keccak256(0),
    ///      zeros[i] = keccak256(zeros[i-1], zeros[i-1]).
    bytes32[TREE_DEPTH] internal _zeros;

    /// @dev Current Merkle root.
    bytes32 public currentRoot;

    /// @dev Historical roots are valid forever so merchants can redeem
    ///      against any root that was current when their note existed.
    mapping(bytes32 => bool) public knownRoots;

    // ================================================================
    // State — nullifiers
    // ================================================================

    mapping(bytes32 => bool) public spentNullifiers;

    // ================================================================
    // Constructor
    // ================================================================

    constructor() {
        _DOMAIN_SEPARATOR = keccak256(abi.encode(
            EIP712_DOMAIN_TYPEHASH,
            DOMAIN_NAME_HASH,
            DOMAIN_VERSION_HASH,
            block.chainid,
            address(this)
        ));

        // Pre-compute zero hashes for each level.
        bytes32 z = keccak256(abi.encodePacked(bytes32(0)));
        _zeros[0] = z;
        for (uint256 i = 1; i < TREE_DEPTH; i++) {
            z = keccak256(abi.encodePacked(z, z));
            _zeros[i] = z;
        }

        // Initial root = zero subtree root at depth TREE_DEPTH
        currentRoot = keccak256(abi.encodePacked(z, z));
        knownRoots[currentRoot] = true;
    }

    // ================================================================
    // Standard session escrow — open
    // ================================================================

    function open(
        address payee,
        address token,
        uint128 deposit,
        bytes32 salt,
        address authorizedSigner,
        bytes32 merchantCommitment
    ) external returns (bytes32 channelId) {
        if (payee == address(0)) revert InvalidPayee();
        if (deposit == 0) revert ZeroDeposit();
        if (merchantCommitment == bytes32(0)) revert InvalidMerchantCommitment();

        channelId = computeChannelId(
            msg.sender, payee, token, salt, authorizedSigner, merchantCommitment
        );

        if (channels[channelId].payer != address(0) || channels[channelId].finalized) {
            revert ChannelAlreadyExists();
        }

        channels[channelId] = Channel({
            finalized: false,
            closeRequestedAt: 0,
            payer: msg.sender,
            payee: payee,
            token: token,
            authorizedSigner: authorizedSigner,
            deposit: deposit,
            settled: 0,
            merchantCommitment: merchantCommitment
        });

        bool ok = IERC20(token).transferFrom(msg.sender, address(this), deposit);
        if (!ok) revert TransferFailed();

        emit ChannelOpened(
            channelId, msg.sender, payee, token,
            authorizedSigner, salt, deposit, merchantCommitment
        );
    }

    // ================================================================
    // Standard session escrow — settle  (+ note minting)
    // ================================================================

    function settle(
        bytes32 channelId,
        uint128 cumulativeAmount,
        bytes calldata signature
    ) external {
        Channel storage ch = channels[channelId];
        _requireActive(ch);
        if (msg.sender != ch.payee) revert NotPayee();
        if (cumulativeAmount > ch.deposit) revert AmountExceedsDeposit();
        if (cumulativeAmount <= ch.settled) revert AmountNotIncreasing();

        _verifyVoucher(ch, channelId, cumulativeAmount, signature);

        uint128 delta = cumulativeAmount - ch.settled;
        ch.settled = cumulativeAmount;

        // === Option A: mint a note commitment for this delta ===
        bytes32 noteRandomness = keccak256(abi.encode(
            channelId, cumulativeAmount, block.timestamp, noteCount
        ));
        bytes32 noteCommitment = _computeNoteCommitment(
            ch.token, delta, ch.merchantCommitment, channelId, noteRandomness
        );
        _insertLeaf(noteCommitment, channelId);

        // Funds stay in the contract — they back the note.

        emit Settled(
            channelId, ch.payer, ch.payee,
            cumulativeAmount, delta, ch.settled
        );
    }

    // ================================================================
    // Standard session escrow — topUp
    // ================================================================

    function topUp(bytes32 channelId, uint256 additionalDeposit) external {
        Channel storage ch = channels[channelId];
        _requireActive(ch);
        if (msg.sender != ch.payer) revert NotPayer();
        if (additionalDeposit == 0) revert ZeroDeposit();
        if (additionalDeposit > type(uint128).max - ch.deposit) revert DepositOverflow();

        ch.deposit += uint128(additionalDeposit);

        bool ok = IERC20(ch.token).transferFrom(msg.sender, address(this), additionalDeposit);
        if (!ok) revert TransferFailed();

        if (ch.closeRequestedAt != 0) {
            ch.closeRequestedAt = 0;
            emit CloseRequestCancelled(channelId, ch.payer, ch.payee);
        }

        emit TopUp(channelId, ch.payer, ch.payee, additionalDeposit, ch.deposit);
    }

    // ================================================================
    // Standard session escrow — close  (+ note minting for residual)
    // ================================================================

    function close(
        bytes32 channelId,
        uint128 cumulativeAmount,
        bytes calldata signature
    ) external {
        Channel storage ch = channels[channelId];
        _requireActive(ch);
        if (msg.sender != ch.payee) revert NotPayee();

        address token = ch.token;
        address payer = ch.payer;
        address payee = ch.payee;
        uint128 deposit = ch.deposit;
        uint128 settledAmount = ch.settled;
        bytes32 mc = ch.merchantCommitment;
        uint128 delta = 0;

        if (cumulativeAmount > settledAmount) {
            if (cumulativeAmount > deposit) revert AmountExceedsDeposit();
            _verifyVoucher(ch, channelId, cumulativeAmount, signature);

            delta = cumulativeAmount - settledAmount;
            settledAmount = cumulativeAmount;

            // Mint note for the final delta
            bytes32 noteRandomness = keccak256(abi.encode(
                channelId, cumulativeAmount, block.timestamp, noteCount
            ));
            bytes32 noteCommitment = _computeNoteCommitment(
                token, delta, mc, channelId, noteRandomness
            );
            _insertLeaf(noteCommitment, channelId);
        }

        uint128 refund = deposit - settledAmount;
        _clearAndFinalize(channelId);

        // Refund unsettled deposit to payer
        if (refund > 0) {
            bool ok = IERC20(token).transfer(payer, refund);
            if (!ok) revert TransferFailed();
        }

        emit ChannelClosed(channelId, payer, payee, settledAmount, refund);
    }

    // ================================================================
    // Standard session escrow — requestClose / withdraw
    // ================================================================

    function requestClose(bytes32 channelId) external {
        Channel storage ch = channels[channelId];
        _requireActive(ch);
        if (msg.sender != ch.payer) revert NotPayer();
        if (ch.closeRequestedAt == 0) {
            ch.closeRequestedAt = uint64(block.timestamp);
            emit CloseRequested(
                channelId, ch.payer, ch.payee,
                block.timestamp + CLOSE_GRACE_PERIOD
            );
        }
    }

    function withdraw(bytes32 channelId) external {
        Channel storage ch = channels[channelId];
        _requireActive(ch);
        if (msg.sender != ch.payer) revert NotPayer();

        bool closeGracePassed = ch.closeRequestedAt != 0
            && block.timestamp >= ch.closeRequestedAt + CLOSE_GRACE_PERIOD;
        if (!closeGracePassed) revert CloseNotReady();

        address token = ch.token;
        address payer = ch.payer;
        address payee = ch.payee;
        uint128 deposit = ch.deposit;
        uint128 settledAmount = ch.settled;
        uint128 refund = deposit - settledAmount;

        _clearAndFinalize(channelId);

        if (refund > 0) {
            bool ok = IERC20(token).transfer(payer, refund);
            if (!ok) revert TransferFailed();
        }

        emit ChannelExpired(channelId, payer, payee);
        emit ChannelClosed(channelId, payer, payee, settledAmount, refund);
    }

    // ================================================================
    // Note redemption
    // ================================================================

    /// @notice Redeem a settled note by proving preimage + membership.
    ///
    /// Merchant provides:
    ///   – The note preimage fields (asset, amount, merchantPubKey,
    ///     blinding, noteRandomness, channelId) so the contract can
    ///     re-derive the commitment.
    ///   – The merchantCommitment = H(merchantPubKey, blinding).
    ///   – The nullifier = H(noteCommitment, merchantPubKey).
    ///   – A Merkle proof against a known root.
    ///   – A recipient address for funds.
    function redeemNote(
        bytes32 noteCommitment,
        bytes32 nullifier,
        address recipient,
        address asset,
        uint128 amount,
        bytes32 merchantPubKey,
        bytes32 blinding,
        bytes32 noteRandomness,
        bytes32 channelId,
        uint256 noteIndex,
        bytes32[] calldata merkleProof
    ) external {
        // 1. Verify merchant commitment preimage
        bytes32 mc = keccak256(abi.encode(merchantPubKey, blinding));

        // 2. Verify note commitment preimage
        bytes32 expectedCommitment = _computeNoteCommitment(
            asset, amount, mc, channelId, noteRandomness
        );
        if (expectedCommitment != noteCommitment) revert InvalidNotePreimage();

        // 3. Verify nullifier
        bytes32 expectedNullifier = keccak256(abi.encode(noteCommitment, merchantPubKey));
        if (expectedNullifier != nullifier) revert InvalidNullifier();
        if (spentNullifiers[nullifier]) revert NullifierAlreadySpent();

        // 4. Verify Merkle membership against any known root
        bytes32 computedRoot = _computeRoot(noteCommitment, noteIndex, merkleProof);
        if (!knownRoots[computedRoot]) revert InvalidMerkleProof();

        // 5. Mark nullifier spent
        spentNullifiers[nullifier] = true;

        // 6. Transfer
        bool ok = IERC20(asset).transfer(recipient, amount);
        if (!ok) revert TransferFailed();

        emit NoteRedeemed(nullifier, recipient, asset, amount);
    }

    // ================================================================
    // View helpers
    // ================================================================

    function getChannel(bytes32 channelId) external view returns (Channel memory) {
        return channels[channelId];
    }

    function computeChannelId(
        address payer,
        address payee,
        address token,
        bytes32 salt,
        address authorizedSigner,
        bytes32 merchantCommitment
    ) public view returns (bytes32) {
        return keccak256(abi.encode(
            payer, payee, token, salt, authorizedSigner,
            merchantCommitment, address(this), block.chainid
        ));
    }

    function getVoucherDigest(
        bytes32 channelId,
        uint128 cumulativeAmount
    ) external view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(VOUCHER_TYPEHASH, channelId, cumulativeAmount));
        return _hashTypedData(structHash);
    }

    function domainSeparator() external view returns (bytes32) {
        return _DOMAIN_SEPARATOR;
    }

    function getMerkleRoot() external view returns (bytes32) {
        return currentRoot;
    }

    // ================================================================
    // Internal — EIP-712
    // ================================================================

    function _hashTypedData(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", _DOMAIN_SEPARATOR, structHash));
    }

    function _verifyVoucher(
        Channel storage ch,
        bytes32 channelId,
        uint128 cumulativeAmount,
        bytes calldata signature
    ) internal view {
        bytes32 structHash = keccak256(abi.encode(VOUCHER_TYPEHASH, channelId, cumulativeAmount));
        bytes32 digest = _hashTypedData(structHash);

        // Recover signer from ECDSA signature
        (bytes32 r, bytes32 s, uint8 v) = _splitSignature(signature);

        // Enforce low-s
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            revert InvalidSignature();
        }

        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert InvalidSignature();

        address expectedSigner = ch.authorizedSigner != address(0)
            ? ch.authorizedSigner
            : ch.payer;

        if (signer != expectedSigner) revert InvalidSignature();
    }

    function _splitSignature(bytes calldata sig)
        internal
        pure
        returns (bytes32 r, bytes32 s, uint8 v)
    {
        if (sig.length != 65) revert InvalidSignature();
        r = bytes32(sig[0:32]);
        s = bytes32(sig[32:64]);
        v = uint8(sig[64]);
    }

    // ================================================================
    // Internal — channel helpers
    // ================================================================

    function _requireActive(Channel storage ch) internal view {
        if (ch.payer == address(0)) revert ChannelNotFound();
        if (ch.finalized) revert ChannelFinalized();
    }

    function _clearAndFinalize(bytes32 channelId) internal {
        delete channels[channelId];
        channels[channelId].finalized = true;
    }

    // ================================================================
    // Internal — note commitment
    // ================================================================

    function _computeNoteCommitment(
        address asset,
        uint128 amount,
        bytes32 merchantCommitment,
        bytes32 channelId,
        bytes32 noteRandomness
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(
            asset, amount, merchantCommitment, channelId, noteRandomness
        ));
    }

    // ================================================================
    // Internal — incremental Merkle tree
    // ================================================================

    /// @dev Insert a leaf into the incremental Merkle tree.
    function _insertLeaf(bytes32 leaf, bytes32 channelId) internal {
        uint256 idx = noteCount;
        if (idx >= MAX_LEAVES) revert TreeFull();

        bytes32 node = leaf;
        uint256 currentIdx = idx;

        for (uint256 i = 0; i < TREE_DEPTH; i++) {
            if (currentIdx & 1 == 0) {
                // Left child — pair with zero, store as filled subtree
                _filledSubtrees[i] = node;
                node = keccak256(abi.encodePacked(node, _zeros[i]));
            } else {
                // Right child — pair with stored left sibling
                node = keccak256(abi.encodePacked(_filledSubtrees[i], node));
            }
            currentIdx >>= 1;
        }

        currentRoot = node;
        knownRoots[node] = true;
        noteCount = idx + 1;

        emit NoteCommitted(idx, leaf, channelId);
    }

    /// @dev Compute the root from a leaf, its index, and siblings.
    function _computeRoot(
        bytes32 leaf,
        uint256 index,
        bytes32[] calldata proof
    ) internal pure returns (bytes32) {
        if (proof.length != TREE_DEPTH) revert InvalidMerkleProof();
        bytes32 node = leaf;
        for (uint256 i = 0; i < TREE_DEPTH; i++) {
            if (index & 1 == 0) {
                node = keccak256(abi.encodePacked(node, proof[i]));
            } else {
                node = keccak256(abi.encodePacked(proof[i], node));
            }
            index >>= 1;
        }
        return node;
    }
}
