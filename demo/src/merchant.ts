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
 * Manages one-time merchant keys for PrivacyEscrowZK sessions.
 *
 * For each session, the merchant generates a fresh keypair. The factory
 * computes a deterministic ChannelPayee address from the one-time key.
 * The server tells the payer to open a channel to that address.
 *
 * The server signs setMerchantCommitment and close operations with the
 * one-time key. Anyone can relay these signed calls to the ChannelPayee
 * contract.
 */
export class MerchantKeyManager {
  /** Merchant's long-term secrets for note redemption (Poseidon field elements) */
  private merchantPubKey: bigint;
  private merchantBlinding: bigint;

  /** Poseidon(merchantPubKey, blinding) as bytes32 */
  readonly merchantCommitment: Hex;

  /** Factory contract address */
  private factoryAddress: Address;

  /** RPC endpoint */
  private rpcUrl: string;

  /** Poseidon hash function (loaded async) */
  private poseidonFn: any;
  private F: any;

  /** Map of session payee address → one-time account */
  private sessions = new Map<
    Address,
    { account: PrivateKeyAccount; deployed: boolean }
  >();

  private constructor(
    merchantPubKey: bigint,
    merchantBlinding: bigint,
    commitment: Hex,
    factoryAddress: Address,
    rpcUrl: string,
    poseidonFn: any,
    F: any,
  ) {
    this.merchantPubKey = merchantPubKey;
    this.merchantBlinding = merchantBlinding;
    this.merchantCommitment = commitment;
    this.factoryAddress = factoryAddress;
    this.rpcUrl = rpcUrl;
    this.poseidonFn = poseidonFn;
    this.F = F;
  }

  static async create(config: {
    /** Merchant's long-term public key (field element as decimal or hex string) */
    merchantPubKey: string;
    /** Merchant's long-term blinding factor (field element as decimal or hex string) */
    merchantBlinding: string;
    /** ChannelPayeeFactory contract address */
    factoryAddress: Address;
    /** RPC URL */
    rpcUrl?: string;
  }): Promise<MerchantKeyManager> {
    const { buildPoseidon } = await import("circomlibjs");
    const poseidonFn = await buildPoseidon();
    const F = poseidonFn.F;

    const pubKey = BigInt(config.merchantPubKey);
    const blinding = BigInt(config.merchantBlinding);

    const h = poseidonFn([F.e(pubKey), F.e(blinding)]);
    const commitment = BigInt(F.toString(h));
    const commitmentHex = ("0x" + commitment.toString(16).padStart(64, "0")) as Hex;

    console.log(`[merchant] Poseidon commitment: ${commitmentHex.slice(0, 18)}…`);

    return new MerchantKeyManager(
      pubKey,
      blinding,
      commitmentHex,
      config.factoryAddress,
      config.rpcUrl ?? "http://localhost:8545",
      poseidonFn,
      F,
    );
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
