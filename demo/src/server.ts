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
  "0x20C000000000000000000000b9537d11c60E8b50";

// PrivacyEscrowZK contract address
const ESCROW_CONTRACT =
  (process.env.ESCROW_CONTRACT as `0x${string}`) ??
  "0x1FAc145aC33A3760B8c1Ed8dEEa5Abb8F3F90bc6";

// ChannelPayeeFactory address
const FACTORY_ADDRESS =
  (process.env.FACTORY_ADDRESS as `0x${string}`) ??
  "0x3b345efa027542e7AdbF052DC81142eaCc6B5092";

// Merchant long-term secrets (Poseidon field elements)
const MERCHANT_PUBKEY = process.env.MERCHANT_PUBKEY ?? "12345";
const MERCHANT_BLINDING = process.env.MERCHANT_BLINDING ?? "67890";

// Price per oracle query
const PRICE_PER_QUERY = process.env.PRICE ?? "0.01";

// RPC
const RPC_URL = process.env.RPC_URL ?? "https://gracious-knuth:goofy-chandrasekhar@rpc.tempo.xyz";

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

async function main() {
  // Initialize merchant key manager (needs async for Poseidon)
  const merchant = await MerchantKeyManager.create({
    merchantPubKey: MERCHANT_PUBKEY,
    merchantBlinding: MERCHANT_BLINDING,
    factoryAddress: FACTORY_ADDRESS,
    rpcUrl: RPC_URL,
  });

  // ---------------------------------------------------------------------------
  // Mppx — per-session dynamic recipient via ChannelPayee
  // ---------------------------------------------------------------------------

  const app = new Hono();

  const mppx = Mppx.create({
    secretKey: process.env.MPP_SECRET_KEY ?? "dev-secret-key",
    methods: [
      tempo.session({
        currency: CURRENCY,
        recipient: "0x0000000000000000000000000000000000000000",
        escrowContract: ESCROW_CONTRACT,
        suggestedDeposit: "1",
      }),
    ],
  });

  // ---------------------------------------------------------------------------
  // Middleware: per-session ChannelPayee recipient
  // ---------------------------------------------------------------------------

  function privacySession(options: { amount: string; unitType: string }) {
    return async (c: any, next: any) => {
      let payeeAddress: string | undefined;

      // On retry the credential embeds the original challenge which contains
      // the recipient. Reuse it so the server's HMAC recomputation matches.
      const auth = c.req.header("authorization");
      if (auth) {
        try {
          const { Credential } = await import("mppx");
          const cred = Credential.deserialize(auth);
          payeeAddress = cred.challenge.request.recipient as string;
        } catch {}
      }

      if (!payeeAddress) {
        payeeAddress = await merchant.createSession();
      }

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
      privacy: "PrivacyEscrowZK — per-session ChannelPayee, ZK note redemption",
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
          privacy: "PrivacyEscrowZK — ZK note redemption, merchant identity hidden",
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
          privacy: "PrivacyEscrowZK — ZK note redemption, merchant identity hidden",
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
║  Powered by MPP tempo.session + PrivacyEscrowZK  ║
╠══════════════════════════════════════════════════╣
║  POST /oracle  { "headline": "..." }             ║
║  GET  /oracle?q=...                              ║
║  Price: ${PRICE_PER_QUERY.padEnd(6)} pathUSD / prediction              ║
║  Escrow: ${ESCROW_CONTRACT.slice(0, 38).padEnd(38)} ║
║  Factory: ${FACTORY_ADDRESS.slice(0, 37).padEnd(37)} ║
║  Privacy: ZK notes + per-session ChannelPayee    ║
╚══════════════════════════════════════════════════╝
  `);

  serve({ fetch: app.fetch, port: PORT }, (info) => {
    console.log(`Listening on http://localhost:${info.port}`);
  });
}

main().catch((e) => {
  console.error("FAILED:", e.message ?? e);
  process.exit(1);
});
