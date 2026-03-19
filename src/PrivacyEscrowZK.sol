// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "./interfaces/IERC20.sol";
import {PoseidonT3} from "poseidon-solidity/PoseidonT3.sol";
import {PoseidonT6} from "poseidon-solidity/PoseidonT6.sol";
import {Groth16Verifier} from "./Groth16Verifier.sol";

/// @title PrivacyEscrowZK
/// @notice ZK version of PrivacyEscrow. Uses Poseidon hashing and Groth16
///         proofs for note redemption so no preimage fields are revealed.
///
/// Changes vs PrivacyEscrow:
///   - Merkle tree uses Poseidon(2) instead of keccak256
///   - Note commitment = Poseidon(asset, amount, merchantCommitment, channelId, noteRandomness)
///   - Nullifier = Poseidon(noteCommitment, merchantPubKey) — verified in ZK
///   - redeemNote takes a Groth16 proof instead of preimage fields
///   - merchantCommitment = Poseidon(merchantPubKey, blinding)
contract PrivacyEscrowZK {

    // ================================================================
    // Constants
    // ================================================================

    uint64 public constant CLOSE_GRACE_PERIOD = 15 minutes;

    bytes32 public constant VOUCHER_TYPEHASH =
        keccak256("Voucher(bytes32 channelId,uint128 cumulativeAmount)");

    uint256 internal constant TREE_DEPTH = 20;
    uint256 internal constant MAX_LEAVES = 1 << TREE_DEPTH;

    // ================================================================
    // EIP-712
    // ================================================================

    bytes32 private constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant DOMAIN_NAME_HASH = keccak256("Tempo Stream Channel");
    bytes32 private constant DOMAIN_VERSION_HASH = keccak256("1");
    bytes32 private immutable _DOMAIN_SEPARATOR;

    // ================================================================
    // Structs
    // ================================================================

    struct Channel {
        bool finalized;
        uint64 closeRequestedAt;
        address payer;
        address payee;
        address token;
        address authorizedSigner;
        uint128 deposit;
        uint128 settled;
        bytes32 merchantCommitment; // Poseidon(merchantPubKey, blinding)
    }

    // ================================================================
    // State
    // ================================================================

    Groth16Verifier public immutable verifier;

    mapping(bytes32 => Channel) public channels;

    uint256 public noteCount;
    uint256[TREE_DEPTH] internal _filledSubtrees;
    uint256[TREE_DEPTH] internal _zeros;
    uint256 public currentRoot;
    mapping(uint256 => bool) public knownRoots;
    mapping(uint256 => bool) public spentNullifiers;

    // ================================================================
    // Events
    // ================================================================

    event ChannelOpened(bytes32 indexed channelId, address indexed payer, address indexed payee,
        address token, address authorizedSigner, bytes32 salt, uint256 deposit);
    event MerchantCommitmentSet(bytes32 indexed channelId, bytes32 merchantCommitment);
    event Settled(bytes32 indexed channelId, address indexed payer, address indexed payee,
        uint256 cumulativeAmount, uint256 deltaPaid, uint256 newSettled);
    event NoteCommitted(uint256 indexed noteIndex, uint256 indexed noteCommitment, bytes32 indexed channelId);
    event NoteRedeemed(uint256 indexed nullifier, address indexed recipient, address asset, uint256 amount);
    event TopUp(bytes32 indexed channelId, address indexed payer, address indexed payee,
        uint256 additionalDeposit, uint256 newDeposit);
    event CloseRequested(bytes32 indexed channelId, address indexed payer, address indexed payee, uint256 closeGraceEnd);
    event CloseRequestCancelled(bytes32 indexed channelId, address indexed payer, address indexed payee);
    event ChannelClosed(bytes32 indexed channelId, address indexed payer, address indexed payee,
        uint256 settledToPayee, uint256 refundedToPayer);
    event ChannelExpired(bytes32 indexed channelId, address indexed payer, address indexed payee);

    // ================================================================
    // Errors
    // ================================================================

    error ChannelAlreadyExists();
    error ChannelNotFound();
    error ChannelFinalized();
    error InvalidSignature();
    error AmountExceedsDeposit();
    error AmountNotIncreasing();
    error NotPayer();
    error NotPayee();
    error TransferFailed();
    error CloseNotReady();
    error InvalidPayee();
    error ZeroDeposit();
    error DepositOverflow();
    error InvalidMerchantCommitment();
    error MerchantCommitmentAlreadySet();
    error MerchantCommitmentNotSet();
    error NullifierAlreadySpent();
    error InvalidProof();
    error TreeFull();

    // ================================================================
    // Constructor
    // ================================================================

    constructor(Groth16Verifier _verifier) {
        verifier = _verifier;

        _DOMAIN_SEPARATOR = keccak256(abi.encode(
            EIP712_DOMAIN_TYPEHASH, DOMAIN_NAME_HASH, DOMAIN_VERSION_HASH,
            block.chainid, address(this)
        ));

        // Pre-compute Poseidon zero hashes for each level
        uint256 z = PoseidonT3.hash([uint256(0), uint256(0)]);
        _zeros[0] = z;
        for (uint256 i = 1; i < TREE_DEPTH; i++) {
            z = PoseidonT3.hash([z, z]);
            _zeros[i] = z;
        }

        currentRoot = PoseidonT3.hash([z, z]);
        knownRoots[currentRoot] = true;
    }

    // ================================================================
    // Channel lifecycle (identical to PrivacyEscrow)
    // ================================================================

    function open(
        address payee, address token, uint128 deposit,
        bytes32 salt, address authorizedSigner
    ) external returns (bytes32 channelId) {
        if (payee == address(0)) revert InvalidPayee();
        if (deposit == 0) revert ZeroDeposit();

        channelId = computeChannelId(msg.sender, payee, token, salt, authorizedSigner);

        if (channels[channelId].payer != address(0) || channels[channelId].finalized)
            revert ChannelAlreadyExists();

        channels[channelId] = Channel({
            finalized: false, closeRequestedAt: 0,
            payer: msg.sender, payee: payee, token: token,
            authorizedSigner: authorizedSigner,
            deposit: deposit, settled: 0, merchantCommitment: bytes32(0)
        });

        bool ok = IERC20(token).transferFrom(msg.sender, address(this), deposit);
        if (!ok) revert TransferFailed();

        emit ChannelOpened(channelId, msg.sender, payee, token, authorizedSigner, salt, deposit);
    }

    function setMerchantCommitment(bytes32 channelId, bytes32 merchantCommitment) external {
        Channel storage ch = channels[channelId];
        _requireActive(ch);
        if (msg.sender != ch.payee) revert NotPayee();
        if (merchantCommitment == bytes32(0)) revert InvalidMerchantCommitment();
        if (ch.merchantCommitment != bytes32(0)) revert MerchantCommitmentAlreadySet();
        ch.merchantCommitment = merchantCommitment;
        emit MerchantCommitmentSet(channelId, merchantCommitment);
    }

    // ================================================================
    // Settle — now uses Poseidon for note commitment
    // ================================================================

    function settle(bytes32 channelId, uint128 cumulativeAmount, bytes calldata signature) external {
        Channel storage ch = channels[channelId];
        _requireActive(ch);
        if (ch.merchantCommitment == bytes32(0)) revert MerchantCommitmentNotSet();
        if (cumulativeAmount > ch.deposit) revert AmountExceedsDeposit();
        if (cumulativeAmount <= ch.settled) revert AmountNotIncreasing();

        _verifyVoucher(ch, channelId, cumulativeAmount, signature);

        uint128 delta = cumulativeAmount - ch.settled;
        ch.settled = cumulativeAmount;

        // Note commitment via Poseidon(5):
        // Poseidon(asset, amount, merchantCommitment, channelId, noteRandomness)
        uint256 noteRandomness = PoseidonT3.hash([
            uint256(keccak256(abi.encode(channelId, cumulativeAmount, block.timestamp, noteCount))),
            uint256(0)
        ]);
        uint256 noteCommitment = PoseidonT6.hash([
            uint256(uint160(ch.token)),
            uint256(delta),
            uint256(ch.merchantCommitment),
            uint256(channelId),
            noteRandomness
        ]);
        _insertLeaf(noteCommitment, channelId);

        emit Settled(channelId, ch.payer, ch.payee, cumulativeAmount, delta, ch.settled);
    }

    // ================================================================
    // TopUp / Close / RequestClose / Withdraw
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

    function close(bytes32 channelId, uint128 cumulativeAmount, bytes calldata signature) external {
        Channel storage ch = channels[channelId];
        _requireActive(ch);
        if (msg.sender != ch.payee) revert NotPayee();
        if (cumulativeAmount > ch.deposit) revert AmountExceedsDeposit();

        if (cumulativeAmount > ch.settled) {
            _verifyVoucher(ch, channelId, cumulativeAmount, signature);

            uint128 delta = cumulativeAmount - ch.settled;
            ch.settled = cumulativeAmount;

            if (ch.merchantCommitment != bytes32(0)) {
                uint256 noteRandomness = PoseidonT3.hash([
                    uint256(keccak256(abi.encode(channelId, cumulativeAmount, block.timestamp, noteCount))),
                    uint256(0)
                ]);
                uint256 noteCommitment = PoseidonT6.hash([
                    uint256(uint160(ch.token)),
                    uint256(delta),
                    uint256(ch.merchantCommitment),
                    uint256(channelId),
                    noteRandomness
                ]);
                _insertLeaf(noteCommitment, channelId);
            }
        }

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

        emit ChannelClosed(channelId, payer, payee, settledAmount, refund);
    }

    function requestClose(bytes32 channelId) external {
        Channel storage ch = channels[channelId];
        _requireActive(ch);
        if (msg.sender != ch.payer) revert NotPayer();
        if (ch.closeRequestedAt == 0) {
            ch.closeRequestedAt = uint64(block.timestamp);
            emit CloseRequested(channelId, ch.payer, ch.payee, block.timestamp + CLOSE_GRACE_PERIOD);
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
    // ZK Note redemption — takes a Groth16 proof, NOT preimage fields
    // ================================================================

    /// @notice Redeem a note using a ZK proof. No preimage fields revealed.
    /// @param proof Groth16 proof: [pA[0], pA[1], pB[0][0], pB[0][1], pB[1][0], pB[1][1], pC[0], pC[1]]
    /// @param nullifier The nullifier (public input, prevents double-spend)
    /// @param merkleRoot The Merkle root the proof was computed against
    /// @param amount The note amount (public input)
    /// @param asset The token address (public input)
    /// @param recipient Where to send funds (public input, bound in proof)
    function redeemNote(
        uint256[8] calldata proof,
        uint256 nullifier,
        uint256 merkleRoot,
        uint128 amount,
        address asset,
        address recipient
    ) external {
        if (spentNullifiers[nullifier]) revert NullifierAlreadySpent();
        if (!knownRoots[merkleRoot]) revert InvalidProof();

        // Public signals: [nullifier, merkleRoot, amount, asset, recipient]
        uint[5] memory pubSignals = [
            nullifier,
            merkleRoot,
            uint256(amount),
            uint256(uint160(asset)),
            uint256(uint160(recipient))
        ];

        bool valid = verifier.verifyProof(
            [proof[0], proof[1]],
            [[proof[2], proof[3]], [proof[4], proof[5]]],
            [proof[6], proof[7]],
            pubSignals
        );
        if (!valid) revert InvalidProof();

        spentNullifiers[nullifier] = true;

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
        address payer, address payee, address token,
        bytes32 salt, address authorizedSigner
    ) public view returns (bytes32) {
        return keccak256(abi.encode(payer, payee, token, salt, authorizedSigner, address(this), block.chainid));
    }

    function getVoucherDigest(bytes32 channelId, uint128 cumulativeAmount) external view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(VOUCHER_TYPEHASH, channelId, cumulativeAmount));
        return _hashTypedData(structHash);
    }

    function domainSeparator() external view returns (bytes32) {
        return _DOMAIN_SEPARATOR;
    }

    function getMerkleRoot() external view returns (uint256) {
        return currentRoot;
    }

    // ================================================================
    // Internal — EIP-712
    // ================================================================

    function _hashTypedData(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", _DOMAIN_SEPARATOR, structHash));
    }

    function _verifyVoucher(
        Channel storage ch, bytes32 channelId,
        uint128 cumulativeAmount, bytes calldata signature
    ) internal view {
        bytes32 structHash = keccak256(abi.encode(VOUCHER_TYPEHASH, channelId, cumulativeAmount));
        bytes32 digest = _hashTypedData(structHash);
        (bytes32 r, bytes32 s, uint8 v) = _splitSignature(signature);
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0)
            revert InvalidSignature();
        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert InvalidSignature();
        address expectedSigner = ch.authorizedSigner != address(0) ? ch.authorizedSigner : ch.payer;
        if (signer != expectedSigner) revert InvalidSignature();
    }

    function _splitSignature(bytes calldata sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
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
    // Internal — Poseidon Merkle tree
    // ================================================================

    function _insertLeaf(uint256 leaf, bytes32 channelId) internal {
        uint256 idx = noteCount;
        if (idx >= MAX_LEAVES) revert TreeFull();

        uint256 node = leaf;
        uint256 currentIdx = idx;

        for (uint256 i = 0; i < TREE_DEPTH; i++) {
            if (currentIdx & 1 == 0) {
                _filledSubtrees[i] = node;
                node = PoseidonT3.hash([node, _zeros[i]]);
            } else {
                node = PoseidonT3.hash([_filledSubtrees[i], node]);
            }
            currentIdx >>= 1;
        }

        currentRoot = node;
        knownRoots[node] = true;
        noteCount = idx + 1;

        emit NoteCommitted(idx, leaf, channelId);
    }
}
