# 🐸 Degen Oracle

Pay-per-prediction contrarian market takes, session-billed via MPP `tempo.session` and powered by `PrivacyEscrow` + `ChannelPayee`.

Feed it a headline. Get an unhinged Polymarket-style prediction with conviction score and thesis. Pay $0.01 per query. Nobody can see which oracle you're consulting — each session gets a fresh one-time keypair and deterministic payee contract. No shared operator. Fully trustless.

## Setup

```bash
cd demo
npm install

# Required: deployed contract addresses
export ESCROW_CONTRACT=0x...
export FACTORY_ADDRESS=0x...

# Required: merchant long-term secrets (for note commitments)
export MERCHANT_PUBKEY=0x...
export MERCHANT_BLINDING=0x...

# Optional
export RPC_URL=http://localhost:8545
export OPENAI_API_KEY=sk-...   # falls back to deterministic takes without

npm run dev
```

## Usage

```bash
# Create a testnet wallet
npx mppx account create

# Query the oracle
npx mppx http://localhost:3000/oracle?q="Fed+cuts+rates+to+zero"

# Or POST
npx mppx -X POST http://localhost:3000/oracle \
  -d '{"headline": "Apple announces Bitcoin treasury strategy"}'
```

## Example response

```json
{
  "oracle": "🐸 DEGEN ORACLE v1",
  "query": "Apple announces Bitcoin treasury strategy",
  "prediction": {
    "market": "Will AAPL outperform BTC in the 90 days following the announcement?",
    "position": "YES",
    "conviction": 82,
    "thesis": "Everyone is buying BTC on the news but 91.3% of corporate treasury announcements lead to a sell-the-news event within 30 days. My source inside Cupertino says Tim Apple is actually hedging against a USD collapse, not going long BTC. The real trade is AAPL calls.",
    "degen_rating": "🐸🐸🐸🐸",
    "nfa_disclaimer": "This is not financial advice. This is a spiritual experience."
  }
}
```

## How privacy works

Each session:

1. Server generates a **one-time keypair**
2. `ChannelPayeeFactory` computes a deterministic `ChannelPayee` contract address
3. Client opens a channel to that address — **standard `open()`, no client changes**
4. Server signs `setMerchantCommitment` + `close` with the one-time key
5. **Anyone** can relay these signed calls — no privileged operator

On-chain observers see:

- ✅ Users funding channels to various contract addresses
- ✅ Normal voucher settlement activity
- ❌ Which merchant each session belongs to
- ❌ Direct merchant payout addresses
- ❌ A payer → merchant revenue graph

Your degen alpha research stays private. 🐸
