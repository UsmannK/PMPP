import {
  generatePrivateKey,
  privateKeyToAccount,
  type PrivateKeyAccount,
} from "viem/accounts";
import {
  createPublicClient,
  createWalletClient,
  http,
  keccak256,
  encodePacked,
  encodeAbiParameters,
  type Address,
  type Hex,
} from "viem";
import { tempo } from "viem/chains";

// ---------------------------------------------------------------------------
// ABI fragments for ChannelPayeeFactory and ChannelPayee
// ---------------------------------------------------------------------------

const factoryAbi = [
  {
    name: "computePayeeAddress",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "merchantKey", type: "address" }],
    outputs: [{ name: "", type: "address" }],
  },
  {
    name: "deploy",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "merchantKey", type: "address" }],
    outputs: [{ name: "payee", type: "address" }],
  },
] as const;

const channelPayeeAbi = [
  {
    name: "setMerchantCommitment",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "channelId", type: "bytes32" },
      { name: "merchantCommitment", type: "bytes32" },
      { name: "merchantSig", type: "bytes" },
    ],
    outputs: [],
  },
  {
    name: "close",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "channelId", type: "bytes32" },
      { name: "cumulativeAmount", type: "uint128" },
      { name: "voucherSignature", type: "bytes" },
      { name: "merchantSig", type: "bytes" },
    ],
    outputs: [],
  },
] as const;

// ---------------------------------------------------------------------------
// MerchantKeyManager
// ---------------------------------------------------------------------------

/**
 * Manages one-time merchant keys for PrivacyEscrow sessions.
 *
 * For each session, the merchant generates a fresh keypair. The factory
 * computes a deterministic ChannelPayee address from the one-time key.
 * The client opens a channel to that address (standard open — no changes).
 *
 * The server signs setMerchantCommitment and close operations with the
 * one-time key. Anyone can relay these signed calls to the ChannelPayee
 * contract.
 */
export class MerchantKeyManager {
  /** Merchant's long-term secrets for note redemption */
  private merchantPubKey: Hex;
  private merchantBlinding: Hex;
  readonly merchantCommitment: Hex;

  /** Factory contract address */
  private factoryAddress: Address;

  /** RPC endpoint */
  private rpcUrl: string;

  /** Map of session payee address → one-time account */
  private sessions = new Map<
    Address,
    { account: PrivateKeyAccount; deployed: boolean }
  >();

  constructor(config: {
    /** Merchant's long-term public key (for note commitments) */
    merchantPubKey: Hex;
    /** Merchant's long-term blinding factor */
    merchantBlinding: Hex;
    /** ChannelPayeeFactory contract address */
    factoryAddress: Address;
    /** RPC URL */
    rpcUrl?: string;
  }) {
    this.merchantPubKey = config.merchantPubKey;
    this.merchantBlinding = config.merchantBlinding;
    this.merchantCommitment = keccak256(
      encodeAbiParameters(
        [{ type: "bytes32" }, { type: "bytes32" }],
        [config.merchantPubKey, config.merchantBlinding]
      )
    );
    this.factoryAddress = config.factoryAddress;
    this.rpcUrl = config.rpcUrl ?? "http://localhost:8545";
  }

  /**
   * Create a new session: generate a one-time key and compute the
   * deterministic ChannelPayee address.
   *
   * @returns The payee address to use as `recipient` in the 402 challenge.
   */
  async createSession(): Promise<Address> {
    const privateKey = generatePrivateKey();
    const account = privateKeyToAccount(privateKey);

    const client = createPublicClient({
      chain: tempo,
      transport: http(this.rpcUrl),
    });

    const payeeAddress = (await client.readContract({
      address: this.factoryAddress,
      abi: factoryAbi,
      functionName: "computePayeeAddress",
      args: [account.address],
    })) as Address;

    this.sessions.set(payeeAddress, { account, deployed: false });

    console.log(
      `[merchant] New session: one-time key ${account.address} → payee ${payeeAddress}`
    );

    return payeeAddress;
  }

  /**
   * Deploy the ChannelPayee contract (if not already deployed) and
   * set the merchant commitment for a channel.
   *
   * Called when the server detects a new channel was opened.
   */
  async bindChannel(payeeAddress: Address, channelId: Hex): Promise<void> {
    const session = this.sessions.get(payeeAddress);
    if (!session) throw new Error(`Unknown session for payee ${payeeAddress}`);

    const walletClient = createWalletClient({
      chain: tempo,
      transport: http(this.rpcUrl),
      account: session.account,
    });

    // Deploy ChannelPayee if needed
    if (!session.deployed) {
      await walletClient.writeContract({
        address: this.factoryAddress,
        abi: factoryAbi,
        functionName: "deploy",
        args: [session.account.address],
      });
      session.deployed = true;
      console.log(`[merchant] Deployed ChannelPayee at ${payeeAddress}`);
    }

    // Sign setMerchantCommitment authorization
    const messageHash = keccak256(
      encodeAbiParameters(
        [
          { type: "string" },
          { type: "bytes32" },
          { type: "bytes32" },
          { type: "address" },
        ],
        ["setMerchantCommitment", channelId, this.merchantCommitment, payeeAddress]
      )
    );
    const sig = await session.account.signMessage({
      message: { raw: messageHash },
    });

    // Submit via the ChannelPayee contract
    await walletClient.writeContract({
      address: payeeAddress,
      abi: channelPayeeAbi,
      functionName: "setMerchantCommitment",
      args: [channelId, this.merchantCommitment, sig],
    });

    console.log(
      `[merchant] Bound commitment to channel ${channelId.slice(0, 10)}...`
    );
  }

  /**
   * Sign a close operation for a channel.
   */
  async closeChannel(
    payeeAddress: Address,
    channelId: Hex,
    cumulativeAmount: bigint,
    voucherSignature: Hex
  ): Promise<void> {
    const session = this.sessions.get(payeeAddress);
    if (!session) throw new Error(`Unknown session for payee ${payeeAddress}`);

    const walletClient = createWalletClient({
      chain: tempo,
      transport: http(this.rpcUrl),
      account: session.account,
    });

    const messageHash = keccak256(
      encodeAbiParameters(
        [
          { type: "string" },
          { type: "bytes32" },
          { type: "uint128" },
          { type: "address" },
        ],
        ["close", channelId, cumulativeAmount, payeeAddress]
      )
    );
    const sig = await session.account.signMessage({
      message: { raw: messageHash },
    });

    await walletClient.writeContract({
      address: payeeAddress,
      abi: channelPayeeAbi,
      functionName: "close",
      args: [channelId, cumulativeAmount, voucherSignature, sig],
    });

    console.log(
      `[merchant] Closed channel ${channelId.slice(0, 10)}...`
    );
  }
}
