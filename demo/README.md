# PrivacyEscrowZK — Demo & Observer

Side-by-side observer UI comparing standard MPP escrow (full payment graph exposed) vs PrivacyEscrowZK (merchant identity hidden via ZK proofs). Polls Tempo mainnet events in real time.

## Setup

```bash
cd demo
npm install
```

## Observer UI

```bash
npx tsx src/observer-compare.ts
# → http://localhost:3001
```

Set `RPC_URL` to use an authenticated Tempo RPC endpoint. Defaults are hardcoded.

The observer shows two columns:
- **Left (Standard):** full payer→merchant graph visible — addresses, amounts, links
- **Right (PrivacyEscrowZK):** merchant identity hidden — notes are opaque, redemptions show only nullifiers + ZK proofs

## Mainnet ZK Simulation

Runs a full end-to-end flow on Tempo mainnet: open channels, settle vouchers, mint Poseidon notes, generate Groth16 proofs, redeem to fresh addresses.

```bash
npx tsx scripts/mainnet-simulate-zk.ts
```

## Presentation

```bash
open slides.html
```
