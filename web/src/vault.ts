import {
  BaseError,
  ContractFunctionRevertedError,
  createPublicClient,
  createWalletClient,
  custom,
  fallback,
  http,
  isAddress,
  parseEther,
  toHex,
  type Address,
  type EIP1193Provider,
  type PublicClient,
  type WalletClient,
} from "viem";
import { crowdVaultAbi, factoryAbi } from "./abi";
import { chainName, type Network } from "./networks";

declare global {
  interface Window {
    ethereum?: EIP1193Provider;
  }
}

import { Phase, type PhaseValue } from "./phase";

export { Phase, type PhaseValue };

export type VaultStatus = {
  phase: PhaseValue;
  claimWindow: bigint; // seconds
  total: bigint;
  threshold: bigint;
  deadline: bigint; // unix seconds, 0 while open
  mine: bigint;
  revealedKey: bigint;
  now: bigint; // chain time, unix seconds
  released: bigint; // the whole pot, once claimed
  recipient: Address;
  campaignKey: string; // compressed SEC1 hex, what creators seal to
};

const env = import.meta.env;
const params = new URLSearchParams(location.search);

/** The demo build always runs the demo. Pages built with VITE_DEMO_BUTTON (and the dev server) offer it as ?demo. */
const DEMO_BUILD = env.VITE_DEFAULT_DEMO === "1";
export const DEMO_BUTTON = !DEMO_BUILD && (env.DEV || env.VITE_DEMO_BUTTON === "1");
/** Demo mode: a pretend vault, with no wallet or network involved. */
export const DEMO = DEMO_BUILD || (DEMO_BUTTON && params.has("demo"));

/** Which network to use, and how to reach it: a custom RPC URL, or "" for the network's own list. */
export type Conn = { net: Network; rpc: string };

/** An error whose message is already written for people. */
export class UserFacingError extends Error {}

const ZERO = "0x0000000000000000000000000000000000000000" as const;

/** Reads go through the RPCs, so visitors without a wallet can see the vault. */
export function readClient({ net, rpc }: Conn): PublicClient | null {
  const urls = rpc ? [rpc] : net.rpcs;
  if (urls.length === 1) return createPublicClient({ chain: net.chain, transport: http(urls[0]) });
  if (urls.length > 1) return createPublicClient({ chain: net.chain, transport: fallback(urls.map((u) => http(u))) });
  if (window.ethereum) return createPublicClient({ chain: net.chain, transport: custom(window.ethereum) });
  return null;
}

export function walletClient(): WalletClient | null {
  return window.ethereum ? createWalletClient({ transport: custom(window.ethereum) }) : null;
}

export function initialVaultAddress(): string {
  const q = params.get("vault");
  return q ?? (env.VITE_VAULT_ADDRESS as string | undefined) ?? "";
}

export { isAddress };

/** Compressed SEC1 encoding of (x, y): 02/03 prefix by y parity, then x. */
export function compressKey(x: bigint, y: bigint): string {
  return (y & 1n ? "03" : "02") + x.toString(16).padStart(64, "0");
}

/** The revealed scalar as 32-byte hex, the form `vault-open open --secret` takes. */
export function keyHex(k: bigint): string {
  return toHex(k, { size: 32 });
}

/**
 * Checks a vault before anything about it is shown: the right network, real
 * code, and created by this site's factory (so it runs genuine CrowdVault
 * code, not a lookalike).
 */
export async function checkVault(client: PublicClient, { net, rpc }: Conn, vault: Address): Promise<"genuine" | "unverified"> {
  const id = await client.getChainId();
  if (id !== net.chain.id) {
    throw new UserFacingError(
      rpc || net.rpcs.length
        ? `That connection serves ${chainName(id)}, not ${net.label}. Check the RPC under Connection.`
        : `Your wallet is on ${chainName(id)}. Switch it to ${net.label} to see this vault.`,
    );
  }
  const code = await client.getCode({ address: vault });
  if (!code || code === "0x") {
    throw new UserFacingError(`No vault at this address on ${net.label}. Check the address and the network.`);
  }
  if (!net.factory) return "unverified";
  const genuine = await client.readContract({
    address: net.factory,
    abi: factoryAbi,
    functionName: "isVault",
    args: [vault],
  });
  if (!genuine) {
    throw new UserFacingError("This address isn't a vault created by this site. Don't send funds to it.");
  }
  return "genuine";
}

export async function loadStatus(client: PublicClient, vault: Address, who?: Address): Promise<VaultStatus> {
  const base = { address: vault, abi: crowdVaultAbi } as const;
  const [s, recipient, kx, ky, claimWindow] = await Promise.all([
    client.readContract({ ...base, functionName: "status", args: [who ?? ZERO] }),
    client.readContract({ ...base, functionName: "recipient" }),
    client.readContract({ ...base, functionName: "keyX" }),
    client.readContract({ ...base, functionName: "keyY" }),
    client.readContract({ ...base, functionName: "claimWindow" }),
  ]).catch((e) => {
    // Without a factory to vouch for it, the address may be some other contract.
    if (e instanceof BaseError && e.walk((c) => c instanceof ContractFunctionRevertedError)) {
      throw new UserFacingError("This address isn't a CrowdVault. Check the address and the network.");
    }
    throw e;
  });
  const [phase, total, threshold, deadline, mine, revealedKey, now, released] = s;
  return {
    phase: phase as PhaseValue,
    claimWindow,
    total,
    threshold,
    deadline,
    mine,
    revealedKey,
    now,
    released,
    recipient,
    campaignKey: compressKey(kx, ky),
  };
}

export async function connect(): Promise<Address> {
  const w = walletClient();
  if (!w) throw new UserFacingError("No browser wallet found. Install one to contribute.");
  const [account] = await w.requestAddresses();
  return account;
}

/** Make sure the wallet is on the chosen network before any transaction. */
async function ensureChain(w: WalletClient, net: Network) {
  const id = net.chain.id;
  if ((await w.getChainId()) === id) return;
  const fail = () => new UserFacingError(`Switch your wallet to ${net.label} to continue.`);
  try {
    await w.switchChain({ id });
  } catch (e) {
    // 4902: the wallet doesn't know this network yet (often the case for testnets).
    if (!(e instanceof BaseError && e.walk((c) => (c as { code?: number }).code === 4902))) throw fail();
    try {
      await w.addChain({ chain: net.chain });
      await w.switchChain({ id });
    } catch {
      throw fail();
    }
  }
  if ((await w.getChainId()) !== id) throw fail();
}

function clients(conn: Conn) {
  const w = walletClient();
  const r = readClient(conn);
  if (!w || !r) throw new UserFacingError("No browser wallet found.");
  return { w, r };
}

// The simulation runs first, so reverts surface before the wallet asks to sign.
export async function contribute(conn: Conn, vault: Address, account: Address, wei: bigint) {
  const { w, r } = clients(conn);
  await ensureChain(w, conn.net);
  const { request } = await r.simulateContract({
    address: vault,
    abi: crowdVaultAbi,
    functionName: "contribute",
    account,
    value: wei,
  });
  const hash = await w.writeContract({ ...request, account, chain: null });
  await r.waitForTransactionReceipt({ hash });
  return hash;
}

export async function withdraw(conn: Conn, vault: Address, account: Address) {
  const { w, r } = clients(conn);
  await ensureChain(w, conn.net);
  const { request } = await r.simulateContract({ address: vault, abi: crowdVaultAbi, functionName: "withdraw", account });
  const hash = await w.writeContract({ ...request, account, chain: null });
  await r.waitForTransactionReceipt({ hash });
  return hash;
}

const ERROR_TEXT: Record<string, string> = {
  WrongPhase: "The vault's state changed. Refresh to see what you can do now.",
  ZeroAmount: "Enter an amount above zero.",
  NothingToWithdraw: "You have nothing in this vault to withdraw.",
  TransferFailed: "The transfer to your address failed.",
  Reentrancy: "Transaction rejected by the vault.",
};

export function explain(err: unknown): string {
  if (err instanceof UserFacingError) return err.message;
  if (err instanceof BaseError) {
    const revert = err.walk((e) => e instanceof ContractFunctionRevertedError);
    if (revert instanceof ContractFunctionRevertedError) {
      const name = revert.data?.errorName;
      if (name && ERROR_TEXT[name]) return ERROR_TEXT[name];
    }
    if (err.name === "HttpRequestError" || err.name === "TimeoutError")
      return "Can't reach the network. Check your internet connection, or choose another RPC under Connection.";
    if (/user (rejected|denied)/i.test(err.message)) return "You cancelled the transaction in your wallet.";
    return err.shortMessage;
  }
  return err instanceof Error ? err.message : String(err);
}

// ============================================================ demo vault

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const DEMO_KEY = 0x5a3d482cafef43f5668a8d2311d75b50c249ac70f2451f772cfc97812a9b9929n;
export const demoAccount = "0x5eA1ed0000000000000000000000000000C0fFEE" as Address;

function demoPhase(s: VaultStatus, phase: PhaseValue): VaultStatus {
  const reached = s.total >= s.threshold ? s.total : parseEther("10.35");
  switch (phase) {
    case Phase.Open:
      return { ...s, phase, total: parseEther("6.4") + s.mine, deadline: 0n, revealedKey: 0n, released: 0n };
    case Phase.Locked:
      return { ...s, phase, total: reached, deadline: s.now + 130_000n, revealedKey: 0n, released: 0n, mine: s.mine || parseEther("0.5") };
    case Phase.Claimed:
      return { ...s, phase, total: 0n, deadline: s.now, revealedKey: DEMO_KEY, released: reached };
    case Phase.Expired:
      return { ...s, phase, total: reached, deadline: s.now - 60n, revealedKey: 0n, released: 0n, mine: s.mine || parseEther("0.5") };
  }
  return s;
}

const demoStartPhase: Record<string, PhaseValue> = { locked: Phase.Locked, unsealed: Phase.Claimed, expired: Phase.Expired };
let demoState: VaultStatus = demoPhase(
  {
    phase: Phase.Open,
    claimWindow: 172_800n,
    total: 0n,
    threshold: parseEther("10"),
    deadline: 0n,
    mine: 0n,
    revealedKey: 0n,
    now: BigInt(Math.floor(Date.now() / 1000)),
    released: 0n,
    recipient: "0x7A3b9e2C51d04F8aE63b1C0d9f2E4a5B6c7D8e9F",
    campaignKey: "032b5da4e881922f799aeed380019ea9a7f866768ccf4b5f3fbe1086c26a893480",
  },
  demoStartPhase[params.get("phase") ?? ""] ?? Phase.Open,
);

/** A pretend vault with the real contract's rules, for demos and design work. */
export const demo = {
  status(): VaultStatus {
    demoState = { ...demoState, now: demoState.now + 12n };
    return demoState;
  },
  setPhase(p: PhaseValue) {
    demoState = demoPhase(demoState, p);
  },
  async contribute(wei: bigint) {
    await sleep(1100);
    const total = demoState.total + wei;
    demoState = { ...demoState, total, mine: demoState.mine + wei };
    if (total >= demoState.threshold) {
      demoState = { ...demoState, phase: Phase.Locked, deadline: demoState.now + demoState.claimWindow };
    }
  },
  async withdraw() {
    await sleep(900);
    demoState = { ...demoState, total: demoState.total - demoState.mine, mine: 0n };
  },
};
