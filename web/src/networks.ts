import { isAddress, type Address, type Chain } from "viem";
import { mainnet, sepolia } from "viem/chains";

export type Network = {
  /** Used in the page's link, e.g. ?network=sepolia. */
  key: string;
  label: string;
  testnet: boolean;
  chain: Chain;
  /** Read-only RPCs, tried in order. Empty means read through the wallet. */
  rpcs: string[];
  /** Only vaults this factory created are shown as genuine. */
  factory?: Address;
};

const env = import.meta.env;

function address(v: unknown): Address | undefined {
  return typeof v === "string" && isAddress(v) ? v : undefined;
}

// Free public endpoints that answer browsers (CORS) without an API key.
// They can be slow or rate-limited; anyone can pick their own under "Connection".
const BUILT_IN: Network[] = [
  {
    key: "mainnet",
    label: "Ethereum",
    testnet: false,
    chain: mainnet,
    rpcs: ["https://ethereum-rpc.publicnode.com", "https://eth.drpc.org", "https://1rpc.io/eth", "https://cloudflare-eth.com"],
    factory: address(env.VITE_FACTORY_MAINNET),
  },
  {
    key: "sepolia",
    label: "Sepolia",
    testnet: true,
    chain: sepolia,
    rpcs: ["https://ethereum-sepolia-rpc.publicnode.com", "https://1rpc.io/sepolia", "https://sepolia.gateway.tenderly.co"],
    factory: address(env.VITE_FACTORY_SEPOLIA),
  },
];

const CHAIN_NAMES: Record<number, string> = {
  1: "Ethereum",
  10: "OP Mainnet",
  8453: "Base",
  42161: "Arbitrum One",
  11155111: "Sepolia",
  31337: "the local test network",
};
export const chainName = (id: number) => CHAIN_NAMES[id] ?? `network ${id}`;

/**
 * A page built with VITE_CHAIN_ID serves that one chain, as before. Without
 * it, visitors choose between Ethereum and the Sepolia testnet.
 */
function configured(): Network[] {
  const fixed = env.VITE_CHAIN_ID ? Number(env.VITE_CHAIN_ID) : undefined;
  if (fixed === undefined) return BUILT_IN;
  const rpc = env.VITE_RPC_URL as string | undefined;
  const known = BUILT_IN.find((n) => n.chain.id === fixed);
  const base: Network = known ?? {
    key: String(fixed),
    label: fixed === 31337 ? "Local network" : chainName(fixed),
    testnet: false,
    chain: {
      id: fixed,
      name: chainName(fixed),
      nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
      rpcUrls: { default: { http: rpc ? [rpc] : [] } },
    },
    rpcs: [],
  };
  return [{ ...base, rpcs: rpc ? [rpc] : base.rpcs, factory: address(env.VITE_FACTORY_ADDRESS) }];
}

export const NETWORKS = configured();
export const CAN_CHOOSE_NETWORK = NETWORKS.length > 1;

export function initialNetwork(): Network {
  const q = new URLSearchParams(location.search).get("network");
  return NETWORKS.find((n) => n.key === q) ?? NETWORKS[0];
}

// A custom RPC may carry an API key, so it's kept in this browser, never in the link.
const rpcKey = (n: Network) => `crowdvault.rpc.${n.key}`;

export function savedRpc(n: Network): string {
  try {
    return localStorage.getItem(rpcKey(n)) ?? "";
  } catch {
    return "";
  }
}

export function saveRpc(n: Network, url: string) {
  try {
    if (url) localStorage.setItem(rpcKey(n), url);
    else localStorage.removeItem(rpcKey(n));
  } catch {
    // Private browsing: the choice lasts for this visit only.
  }
}
