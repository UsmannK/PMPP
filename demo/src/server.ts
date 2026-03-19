import { Hono } from "hono";
import { Mppx, tempo } from "mppx/hono";
import { serve } from "@hono/node-server";
import { generateTake } from "./oracle.js";
import { MerchantKeyManager } from "./merchant.js";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const PORT = Number(process.env.PORT ?? 3000);

// pathUSD on Tempo
const CURRENCY =
  (process.env.CURRENCY as `0x${string}`) ??
  "0x20c0000000000000000000000000000000000000";

// PrivacyEscrow contract address
const ESCROW_CONTRACT =
  (process.env.ESCROW_CONTRACT as `0x${string}`) ??
  (() => { throw new Error("ESCROW_CONTRACT is required"); })();

// ChannelPayeeFactory address
const FACTORY_ADDRESS =
  (process.env.FACTORY_ADDRESS as `0x${string}`) ??
  (() => { throw new Error("FACTORY_ADDRESS is required"); })();

// Merchant long-term secrets (in production, loaded from secure storage)
const MERCHANT_PUBKEY =
  (process.env.MERCHANT_PUBKEY as `0x${string}`) ??
  (() => { throw new Error("MERCHANT_PUBKEY is required"); })();
const MERCHANT_BLINDING =
  (process.env.MERCHANT_BLINDING as `0x${string}`) ??
  (() => { throw new Error("MERCHANT_BLINDING is required"); })();

// Price per oracle query
const PRICE_PER_QUERY = process.env.PRICE ?? "0.01";

// RPC
const RPC_URL = process.env.RPC_URL ?? "http://localhost:8545";

// ---------------------------------------------------------------------------
// Merchant key manager
// ---------------------------------------------------------------------------

const merchant = new MerchantKeyManager({
  merchantPubKey: MERCHANT_PUBKEY,
  merchantBlinding: MERCHANT_BLINDING,
  factoryAddress: FACTORY_ADDRESS,
  rpcUrl: RPC_URL,
});

// ---------------------------------------------------------------------------
// Mppx — per-session dynamic recipient via ChannelPayee
// ---------------------------------------------------------------------------

const app = new Hono();

// The recipient set here is a placeholder — overridden per-session below.
const mppx = Mppx.create({
  methods: [
    tempo.session({
      currency: CURRENCY,
      recipient: "0x0000000000000000000000000000000000000000",
      escrowContract: ESCROW_CONTRACT,
      suggestedDeposit: "1",
      testnet: true,
    }),
  ],
});

// ---------------------------------------------------------------------------
// Middleware: per-session ChannelPayee recipient
// ---------------------------------------------------------------------------

function privacySession(options: { amount: string; unitType: string }) {
  return async (c: any, next: any) => {
    const payeeAddress = await merchant.createSession();
    const handler = mppx.session({
      amount: options.amount,
      unitType: options.unitType,
      recipient: payeeAddress,
    });
    return handler(c, next);
  };
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

app.get("/", (c) =>
  c.json({
    name: "🐸 Degen Oracle",
    description: "Pay-per-prediction contrarian market takes",
    price: `${PRICE_PER_QUERY} pathUSD per query`,
    privacy: "Fully trustless — per-session ChannelPayee, no shared operator",
    usage: 'POST /oracle { "headline": "your topic here" }',
    endpoints: {
      "GET /": "this message",
      "POST /oracle": "get a degen take (session-billed)",
      "GET /oracle?q=...": "get a degen take (session-billed)",
    },
  })
);

app.post(
  "/oracle",
  privacySession({ amount: PRICE_PER_QUERY, unitType: "prediction" }),
  async (c) => {
    const body = await c.req.json().catch(() => ({}));
    const headline =
      (body as Record<string, unknown>).headline ??
      (body as Record<string, unknown>).topic ??
      (body as Record<string, unknown>).q ??
      "Something is happening in the world";

    const take = await generateTake(String(headline));

    return c.json({
      oracle: "🐸 DEGEN ORACLE v1",
      query: headline,
      prediction: take,
      _meta: {
        price: `${PRICE_PER_QUERY} pathUSD`,
        privacy: "fully trustless — per-session ChannelPayee, no shared operator",
        escrow: ESCROW_CONTRACT,
      },
    });
  }
);

app.get(
  "/oracle",
  privacySession({ amount: PRICE_PER_QUERY, unitType: "prediction" }),
  async (c) => {
    const headline =
      c.req.query("q") ??
      c.req.query("headline") ??
      "Markets are doing market things";

    const take = await generateTake(headline);

    return c.json({
      oracle: "🐸 DEGEN ORACLE v1",
      query: headline,
      prediction: take,
      _meta: {
        price: `${PRICE_PER_QUERY} pathUSD`,
        privacy: "fully trustless — per-session ChannelPayee, no shared operator",
        escrow: ESCROW_CONTRACT,
      },
    });
  }
);

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

console.log(`
╔══════════════════════════════════════════════════╗
║           🐸  DEGEN ORACLE  🐸                   ║
║  Pay-per-prediction contrarian market takes      ║
║  Powered by MPP tempo.session + PrivacyEscrow    ║
╠══════════════════════════════════════════════════╣
║  POST /oracle  { "headline": "..." }             ║
║  GET  /oracle?q=...                              ║
║  Price: ${PRICE_PER_QUERY.padEnd(6)} pathUSD / prediction              ║
║  Escrow: ${ESCROW_CONTRACT.slice(0, 38).padEnd(38)} ║
║  Factory: ${FACTORY_ADDRESS.slice(0, 37).padEnd(37)} ║
║  Privacy: TRUSTLESS (per-session ChannelPayee)   ║
╚══════════════════════════════════════════════════╝
`);

serve({ fetch: app.fetch, port: PORT }, (info) => {
  console.log(`Listening on http://localhost:${info.port}`);
});
