// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IPrivacyEscrow
/// @notice MPP-compatible tempo.session escrow with merchant privacy.
/// @dev Drop-in replacement for TempoStreamChannel. The server sets
///      `methodDetails.escrowContract` to this contract. Channels bind a
///      hidden merchantCommitment at open time. On every `settle()`, the
///      delta is immediately converted into a Merkle-tree note commitment
///      (Option A — fully trustless per-settle note minting). Merchants
///      later redeem notes privately via membership proofs + nullifiers.
interface IPrivacyEscrow {

    // ----------------------------------------------------------------
    // Structs
    // ----------------------------------------------------------------

    struct Channel {
        bool finalized;
        uint64 closeRequestedAt;
        address payer;
        address payee;          // shared server/operator address
        address token;
        address authorizedSigner;
        uint128 deposit;
        uint128 settled;
        bytes32 merchantCommitment; // H(merchantPubKey, blinding)
    }

    // ----------------------------------------------------------------
    // Standard session escrow functions (MPP-compatible)
    // ----------------------------------------------------------------

    function CLOSE_GRACE_PERIOD() external view returns (uint64);
    function VOUCHER_TYPEHASH() external view returns (bytes32);

    /// @notice Open a session channel bound to a hidden merchant.
    /// @param merchantCommitment  H(merchantPubKey ‖ blinding). Binds this
    ///        channel's settled value to a specific merchant without
    ///        revealing identity on-chain.
    function open(
        address payee,
        address token,
        uint128 deposit,
        bytes32 salt,
        address authorizedSigner,
        bytes32 merchantCommitment
    ) external returns (bytes32 channelId);

    function settle(bytes32 channelId, uint128 cumulativeAmount, bytes calldata signature) external;
    function topUp(bytes32 channelId, uint256 additionalDeposit) external;
    function close(bytes32 channelId, uint128 cumulativeAmount, bytes calldata signature) external;
    function requestClose(bytes32 channelId) external;
    function withdraw(bytes32 channelId) external;

    function getChannel(bytes32 channelId) external view returns (Channel memory);
    function computeChannelId(
        address payer,
        address payee,
        address token,
        bytes32 salt,
        address authorizedSigner,
        bytes32 merchantCommitment
    ) external view returns (bytes32);
    function getVoucherDigest(bytes32 channelId, uint128 cumulativeAmount) external view returns (bytes32);
    function domainSeparator() external view returns (bytes32);

    // ----------------------------------------------------------------
    // Privacy / note-tree functions
    // ----------------------------------------------------------------

    /// @notice Redeem a note by proving membership + ownership.
    /// @param noteCommitment  The leaf that was appended on settle.
    /// @param nullifier       keccak256(noteCommitment, secret).
    /// @param recipient       Where to send the redeemed funds.
    /// @param asset            Token address.
    /// @param amount          Amount encoded in the note.
    /// @param merchantPubKey  Merchant public key (preimage of commitment).
    /// @param blinding        Random blinding factor (preimage of commitment).
    /// @param noteRandomness  Randomness used when the note was created.
    /// @param channelId       Channel the note originated from.
    /// @param noteIndex       Index of the note in the tree.
    /// @param merkleProof     Siblings for the Merkle path.
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
    ) external;

    /// @return The current Merkle root of the note tree.
    function getMerkleRoot() external view returns (bytes32);

    /// @return The number of notes inserted so far.
    function noteCount() external view returns (uint256);

    // ----------------------------------------------------------------
    // Events
    // ----------------------------------------------------------------

    event ChannelOpened(
        bytes32 indexed channelId,
        address indexed payer,
        address indexed payee,
        address token,
        address authorizedSigner,
        bytes32 salt,
        uint256 deposit,
        bytes32 merchantCommitment
    );

    event Settled(
        bytes32 indexed channelId,
        address indexed payer,
        address indexed payee,
        uint256 cumulativeAmount,
        uint256 deltaPaid,
        uint256 newSettled
    );

    event NoteCommitted(
        uint256 indexed noteIndex,
        bytes32 indexed noteCommitment,
        bytes32 indexed channelId
    );

    event NoteRedeemed(
        bytes32 indexed nullifier,
        address indexed recipient,
        address asset,
        uint256 amount
    );

    event TopUp(
        bytes32 indexed channelId,
        address indexed payer,
        address indexed payee,
        uint256 additionalDeposit,
        uint256 newDeposit
    );

    event CloseRequested(
        bytes32 indexed channelId,
        address indexed payer,
        address indexed payee,
        uint256 closeGraceEnd
    );

    event CloseRequestCancelled(
        bytes32 indexed channelId,
        address indexed payer,
        address indexed payee
    );

    event ChannelClosed(
        bytes32 indexed channelId,
        address indexed payer,
        address indexed payee,
        uint256 settledToPayee,
        uint256 refundedToPayer
    );

    event ChannelExpired(
        bytes32 indexed channelId,
        address indexed payer,
        address indexed payee
    );

    // ----------------------------------------------------------------
    // Errors
    // ----------------------------------------------------------------

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
    error InvalidToken();
    error ZeroDeposit();
    error DepositOverflow();
    error InvalidMerchantCommitment();
    error InvalidNullifier();
    error NullifierAlreadySpent();
    error InvalidMerkleProof();
    error InvalidNotePreimage();
    error TreeFull();
}
