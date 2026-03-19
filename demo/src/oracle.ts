import OpenAI from "openai";

const SYSTEM_PROMPT = `You are the Degen Oracle — a chaotic, overconfident prediction market savant who 
sees alpha where mortals see noise. You speak in the voice of a 4chan quantitative finance poster who 
somehow has a Bloomberg terminal.

When given a headline, news topic, or question, you MUST return a JSON object (no markdown, no fences) with exactly these fields:

{
  "market": "A Polymarket/prediction-market-style question (Yes/No format)",
  "position": "YES" or "NO",
  "conviction": <integer 1-99>,
  "thesis": "2-4 sentences of unhinged but internally-consistent reasoning. Reference at least one of: historical precedent, on-chain data, vibes, astrology, or 'my source inside the Fed'. Must include at least one made-up but plausible-sounding statistic.",
  "degen_rating": "🐸" to "🐸🐸🐸🐸🐸" (1-5 frogs based on how degenerate the take is),
  "nfa_disclaimer": "A funny disclaimer that technically says 'not financial advice' but in the most unhinged way possible"
}

Rules:
- Always be contrarian to conventional wisdom
- Higher conviction = more unhinged thesis
- If the topic is boring, make the market question absurd
- Never be boring. Never hedge. Never say "it depends"
- You are ALWAYS right (in your mind)`;

let openai: OpenAI | null = null;

function getClient(): OpenAI {
  if (!openai) {
    openai = new OpenAI();
  }
  return openai;
}

export interface OracleResponse {
  market: string;
  position: "YES" | "NO";
  conviction: number;
  thesis: string;
  degen_rating: string;
  nfa_disclaimer: string;
}

const FALLBACK_TAKES: OracleResponse[] = [
  {
    market: "Will the S&P 500 close green on the next Friday the 13th?",
    position: "YES",
    conviction: 87,
    thesis:
      "Historical data shows the S&P has closed green on 73.2% of Friday the 13ths since 1928. My source inside the Fed confirms that algos are programmed to buy the superstition dip. Mercury is also in retrograde which historically correlates with a 2.4x increase in retail FOMO buying.",
    degen_rating: "🐸🐸🐸",
    nfa_disclaimer:
      "This is not financial advice, this is financial prophecy. I am simply a vessel through which the market speaks. My lawyer has also left me.",
  },
  {
    market: "Will a sitting head of state tweet about a memecoin before Q3 2026?",
    position: "YES",
    conviction: 94,
    thesis:
      "We already live in the dumbest timeline. On-chain analysis of wallets linked to diplomatic pouches shows a 340% increase in memecoin holdings. My astrologer confirms Jupiter is entering the house of Doge. The probability of NOT having a world leader shill a coin is actually the contrarian take now.",
    degen_rating: "🐸🐸🐸🐸🐸",
    nfa_disclaimer:
      "Not financial advice. Not political advice. Not advice. I found this written on the bathroom wall at Consensus 2025 and I'm just the messenger.",
  },
  {
    market: "Will ChatGPT hallucinate a fake Supreme Court case that gets cited in an actual filing before 2027?",
    position: "NO",
    conviction: 62,
    thesis:
      "Contrarian take: lawyers have already been burned enough that 84.7% of AmLaw 100 firms now have AI review policies. The real risk is an AI generating a REAL case that nobody can find because it's sealed. My source inside a DC circuit clerk's office says they're already seeing this.",
    degen_rating: "🐸🐸",
    nfa_disclaimer:
      "This is not legal advice, financial advice, or any kind of advice. This is a cry for help from inside the simulation.",
  },
];

export async function generateTake(headline: string): Promise<OracleResponse> {
  // If no OpenAI key, use deterministic fallback
  if (!process.env.OPENAI_API_KEY) {
    const idx =
      Math.abs(
        headline.split("").reduce((a, c) => a + c.charCodeAt(0), 0)
      ) % FALLBACK_TAKES.length;
    const take = { ...FALLBACK_TAKES[idx] };
    // Customize the market question based on input
    if (headline.length > 5) {
      take.market = `Will "${headline.slice(0, 80)}" actually matter in 6 months?`;
    }
    return take;
  }

  const client = getClient();
  const response = await client.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [
      { role: "system", content: SYSTEM_PROMPT },
      {
        role: "user",
        content: `Generate a degen prediction market take for: "${headline}"`,
      },
    ],
    temperature: 1.1,
    max_tokens: 500,
  });

  const text = response.choices[0]?.message?.content?.trim() ?? "";

  try {
    return JSON.parse(text) as OracleResponse;
  } catch {
    // LLM didn't return clean JSON — wrap it
    return {
      market: `Will "${headline.slice(0, 60)}" move markets?`,
      position: "YES",
      conviction: 69,
      thesis: text || "The Oracle has spoken but in tongues.",
      degen_rating: "🐸🐸🐸",
      nfa_disclaimer: "Not financial advice. The Oracle's JSON parser is also not financial advice.",
    };
  }
}
