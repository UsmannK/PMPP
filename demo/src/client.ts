import { Mppx, session } from "mppx/client";
import { privateKeyToAccount } from "viem/accounts";

const TEMPO_KEY = "0xd9c7165d29e9b3ece5265a371dcdc2fada6c7acec02c632309f9faea37c9a3f1";
const ESCROW_CONTRACT = "0x1FAc145aC33A3760B8c1Ed8dEEa5Abb8F3F90bc6";
const RPC_URL = "https://gracious-knuth:goofy-chandrasekhar@rpc.tempo.xyz";

const account = privateKeyToAccount(TEMPO_KEY);

const mppx = Mppx.create({
  methods: [
    session({
      account,
      escrowContract: ESCROW_CONTRACT,
      maxDeposit: "0.05",
      rpcUrl: { 4217: RPC_URL },
    }),
  ],
});

const query = process.argv[2] ?? "the US government is suppressing oil prices";

const res = await mppx.fetch(
  `http://localhost:3000/oracle?q=${encodeURIComponent(query)}`
);
const data = await res.json();
console.log(JSON.stringify(data, null, 2));
