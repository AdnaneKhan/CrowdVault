import { useCallback, useEffect, useMemo, useState } from "react";
import { formatEther, parseEther, type Address } from "viem";
import { Cipherfield } from "./Cipherfield";
import { Seal } from "./Seal";
import { CAN_CHOOSE_NETWORK, NETWORKS, initialNetwork, saveRpc, savedRpc, type Network } from "./networks";
import {
  DEMO,
  DEMO_BUTTON,
  Phase,
  checkVault,
  connect,
  contribute,
  demo,
  demoAccount,
  explain,
  initialVaultAddress,
  isAddress,
  keyHex,
  loadStatus,
  readClient,
  withdraw,
  type Conn,
  type PhaseValue,
  type VaultStatus,
} from "./vault";

const PRESETS = ["0.05", "0.1", "0.5", "1"];
const HEX = "0123456789abcdef";
const DEMO_VAULT = "0x0000000000000000000000000000000000000000" as Address;

function eth(wei: bigint): string {
  const n = Number(formatEther(wei));
  if (n === 0) return "0";
  if (n >= 1000) return Math.round(n).toLocaleString("en-US");
  const s = n >= 1 ? n.toFixed(2) : n.toPrecision(2);
  return s.includes(".") ? s.replace(/\.?0+$/, "") : s;
}

function short(a: string): string {
  return `${a.slice(0, 6)}…${a.slice(-4)}`;
}

function ratio(a: bigint, b: bigint): number {
  return b > 0n ? Number((a * 10000n) / b) / 10000 : 0;
}

function roughTime(seconds: bigint): string {
  const s = Number(seconds > 0n ? seconds : 0n);
  if (s < 90) return "about a minute";
  if (s < 5400) return `about ${Math.round(s / 60)} minutes`;
  if (s < 129600) return `about ${Math.round(s / 3600)} hours`;
  return `about ${Math.round(s / 86400)} days`;
}

function duration(seconds: bigint): string {
  const s = Number(seconds);
  if (s % 86400 === 0) return `${s / 86400} day${s === 86400 ? "" : "s"}`;
  if (s % 3600 === 0) return `${s / 3600} hour${s === 3600 ? "" : "s"}`;
  return roughTime(seconds).replace("about ", "");
}

function when(unix: bigint): string {
  return new Date(Number(unix) * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

const reduceMotion = () => matchMedia("(prefers-reduced-motion: reduce)").matches;
const scramble = (s: string) => s.replace(/./g, () => HEX[(Math.random() * 16) | 0]);

/** The revealed key, decoding itself into place once. */
function DecodedKey({ value }: { value: string }) {
  const body = value.slice(2);
  const [shown, setShown] = useState(() => (reduceMotion() ? body : scramble(body)));
  useEffect(() => {
    if (reduceMotion()) {
      setShown(body);
      return;
    }
    const start = performance.now();
    const id = setInterval(() => {
      const p = Math.min(1, (performance.now() - start) / 1500);
      const done = Math.floor(p * body.length);
      setShown(body.slice(0, done) + scramble(body.slice(done)));
      if (p === 1) clearInterval(id);
    }, 40);
    return () => clearInterval(id);
  }, [body]);
  return (
    <code className="key-value" aria-label={value}>
      <span className="key-prefix">0x</span>
      {(shown.match(/.{1,8}/g) ?? []).map((g, i) => (
        <span key={i} className="key-group">
          {g}
        </span>
      ))}
    </code>
  );
}

function Copy({ text, label, className = "btn-quiet" }: { text: string; label: string; className?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className={className}
      onClick={async () => {
        await navigator.clipboard.writeText(text);
        setDone(true);
        setTimeout(() => setDone(false), 1600);
      }}
    >
      {done ? "Copied" : label}
    </button>
  );
}

function PhaseTrack({ phase }: { phase: PhaseValue }) {
  const failed = phase === Phase.Expired;
  const at = phase === Phase.Open ? 0 : phase === Phase.Locked ? 1 : 2;
  const steps = ["Open", "Goal reached", failed ? "Refunds open" : "Unsealed"];
  return (
    <ol className={`track${failed ? " is-failed" : ""}`} aria-label="Vault progress">
      {steps.map((label, i) => (
        <li key={label} data-state={i < at ? "done" : i === at ? "current" : "todo"} aria-current={i === at ? "step" : undefined}>
          <span className="track-dot" />
          <span>{label}</span>
        </li>
      ))}
    </ol>
  );
}

function Mark() {
  return (
    <svg className="mark" viewBox="0 0 24 24" aria-hidden="true">
      <circle cx="12" cy="12" r="10.5" className="mark-wax" />
      <path d="M12 6.2a2.6 2.6 0 0 1 1.5 4.7l.9 6.1h-4.8l.9-6.1A2.6 2.6 0 0 1 12 6.2z" className="mark-hole" />
    </svg>
  );
}

function NetworkPicker({ net, onChange }: { net: Network; onChange: (n: Network) => void }) {
  return (
    <div className="seg seg-net" role="group" aria-label="Network">
      {NETWORKS.map((n) => (
        <button key={n.key} type="button" aria-pressed={n.key === net.key} onClick={() => onChange(n)}>
          {n.label}
          {n.testnet && <span className="seg-note"> testnet</span>}
        </button>
      ))}
    </div>
  );
}

/** Which RPC the page reads through: the network's public list, one of them, or the visitor's own. */
function Connection({ conn, onRpc }: { conn: Conn; onRpc: (url: string) => void }) {
  const { net, rpc } = conn;
  const isCustom = rpc !== "" && !net.rpcs.includes(rpc);
  const [editing, setEditing] = useState(isCustom);
  const [draft, setDraft] = useState(isCustom ? rpc : "");
  const [bad, setBad] = useState(false);
  return (
    <details className="creators connection">
      <summary>Connection</summary>
      <p>
        How this page reads {net.label}. Contributions and withdrawals always go through your wallet. Public RPCs are
        free but can be slow; use your own if they struggle.
      </p>
      <label htmlFor="rpc">RPC</label>
      <select
        id="rpc"
        className="text-field"
        value={editing ? "custom" : rpc}
        onChange={(e) => {
          const v = e.target.value;
          if (v === "custom") return setEditing(true);
          setEditing(false);
          onRpc(v);
        }}
      >
        <option value="">{net.rpcs.length ? "Automatic: the public RPCs, in turn" : "Your wallet"}</option>
        {net.rpcs.map((u) => (
          <option key={u} value={u}>
            {new URL(u).host}
          </option>
        ))}
        <option value="custom">Your own RPC URL…</option>
      </select>
      {editing && (
        <form
          className="rpc-custom"
          onSubmit={(e) => {
            e.preventDefault();
            const u = draft.trim();
            const ok = /^https?:\/\/\S+$/.test(u);
            setBad(!ok);
            if (ok) onRpc(u);
          }}
        >
          <input
            className="text-field"
            type="url"
            aria-label="Your RPC URL"
            placeholder="https://…"
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            spellCheck={false}
            autoComplete="off"
          />
          <button type="submit" className="btn-line">
            Use
          </button>
        </form>
      )}
      {bad && <p className="hint left">Enter a URL starting with https://</p>}
      {editing && <p className="hint left">Saved in this browser only, never in the page's link.</p>}
    </details>
  );
}

export function App() {
  const startAddr = initialVaultAddress();
  const [vaultInput, setVaultInput] = useState(startAddr);
  const [vault, setVault] = useState<Address | null>(
    DEMO ? DEMO_VAULT : isAddress(startAddr) ? (startAddr as Address) : null,
  );
  const [net, setNet] = useState(initialNetwork);
  const [rpc, setRpc] = useState(() => savedRpc(net));
  const conn = useMemo<Conn>(() => ({ net, rpc }), [net, rpc]);
  const [account, setAccount] = useState<Address | null>(null);
  const [status, setStatus] = useState<VaultStatus | null>(null);
  const [trust, setTrust] = useState<"genuine" | "unverified" | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [amountIn, setAmountIn] = useState("");
  const [busy, setBusy] = useState<null | "contribute" | "withdraw" | "connect">(null);
  const [notice, setNotice] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  const refresh = useCallback(async () => {
    if (DEMO) {
      setStatus(demo.status());
      return;
    }
    if (!vault) return;
    const client = readClient(conn);
    if (!client) {
      setLoadError("Install a browser wallet to view and fund this vault.");
      return;
    }
    try {
      setTrust(await checkVault(client, conn, vault));
      setStatus(await loadStatus(client, vault, account ?? undefined));
      setLoadError(null);
    } catch (e) {
      setStatus(null);
      setLoadError(explain(e));
    }
  }, [vault, account, conn]);

  // Keep the link shareable: it names the network and the vault.
  useEffect(() => {
    if (DEMO) return;
    const q = new URLSearchParams();
    if (CAN_CHOOSE_NETWORK) q.set("network", net.key);
    if (vault) q.set("vault", vault);
    history.replaceState(null, "", `?${q}`);
  }, [net, vault]);

  function chooseNetwork(n: Network) {
    if (n.key === net.key) return;
    setNet(n);
    setRpc(savedRpc(n));
    setStatus(null);
    setTrust(null);
    setLoadError(null);
    setNotice(null);
  }

  function chooseRpc(url: string) {
    saveRpc(net, url);
    setRpc(url);
    setStatus(null);
    setLoadError(null);
  }

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 5000);
    return () => clearInterval(id);
  }, [refresh]);

  useEffect(() => {
    const provider = window.ethereum;
    if (DEMO || !provider) return;
    const onAccounts = (a: unknown) => setAccount(((a as Address[])[0] ?? null) as Address | null);
    const onChain = () => refresh();
    provider.on("accountsChanged", onAccounts);
    provider.on("chainChanged", onChain);
    return () => {
      provider.removeListener("accountsChanged", onAccounts);
      provider.removeListener("chainChanged", onChain);
    };
  }, [refresh]);

  async function run(kind: "contribute" | "withdraw" | "connect", fn: () => Promise<string | void>) {
    setBusy(kind);
    setNotice(null);
    try {
      const text = await fn();
      if (text) setNotice({ kind: "ok", text });
      await refresh();
    } catch (e) {
      setNotice({ kind: "err", text: explain(e) });
    } finally {
      setBusy(null);
    }
  }

  function openVault(e: React.FormEvent) {
    e.preventDefault();
    const a = vaultInput.trim();
    if (!isAddress(a)) {
      setNotice({ kind: "err", text: "That isn't a valid address. It starts with 0x and is 42 characters long." });
      return;
    }
    setVault(a as Address);
    setNotice(null);
  }

  const wei = (() => {
    try {
      const w = parseEther(amountIn.trim() || "0");
      return w > 0n ? w : null;
    } catch {
      return null;
    }
  })();

  const onConnect = () =>
    run("connect", async () => {
      setAccount(DEMO ? demoAccount : await connect());
    });

  const onContribute = (e: React.FormEvent) => {
    e.preventDefault();
    if (!vault || !account) return;
    if (!wei) {
      setNotice({ kind: "err", text: "Enter an amount in ETH, like 0.25." });
      return;
    }
    run("contribute", async () => {
      if (DEMO) await demo.contribute(wei);
      else await contribute(conn, vault, account, wei);
      setAmountIn("");
      return `Contributed ${eth(wei)} ETH.`;
    });
  };

  const onWithdraw = () => {
    if (!vault || !account || !status) return;
    const mine = status.mine;
    run("withdraw", async () => {
      if (DEMO) await demo.withdraw();
      else await withdraw(conn, vault, account);
      return `Withdrew ${eth(mine)} ETH.`;
    });
  };

  const s = status;
  const phaseName = !s ? "loading" : ["open", "locked", "unsealed", "expired"][s.phase];
  const timeLeft = s && s.phase === Phase.Locked ? s.deadline - s.now : 0n;
  const fill = !s
    ? 0
    : s.phase === Phase.Open
      ? ratio(s.total, s.threshold)
      : s.phase === Phase.Locked
        ? ratio(timeLeft, s.claimWindow)
        : s.phase === Phase.Claimed
          ? 1
          : 0;

  function shareHint(st: VaultStatus, w: bigint): string {
    if (st.total + w >= st.threshold) return "This reaches the goal. Withdrawals pause while the key is released.";
    const pct = Number((w * 1000n) / st.threshold) / 10;
    return `That's ${pct < 0.1 ? "under 0.1" : pct}% of the goal.`;
  }

  return (
    <div className={`page is-${phaseName}${DEMO ? " has-demo" : ""}`}>
      <header className="top">
        <span className="wordmark">
          <Mark />
          CrowdVault
        </span>
        {!DEMO && vault && (
          <span className={`net${net.testnet ? " is-test" : ""}`}>
            {CAN_CHOOSE_NETWORK ? (
              <select
                aria-label="Network"
                value={net.key}
                onChange={(e) => chooseNetwork(NETWORKS.find((n) => n.key === e.target.value)!)}
              >
                {NETWORKS.map((n) => (
                  <option key={n.key} value={n.key}>
                    {n.label}
                    {n.testnet ? " (testnet)" : ""}
                  </option>
                ))}
              </select>
            ) : (
              <>
                {net.label}
                {net.testnet ? " (testnet)" : ""}
              </>
            )}
          </span>
        )}
        {account ? (
          <span className="acct" title={account}>
            {short(account)}
          </span>
        ) : (
          <button type="button" className="btn-quiet" disabled={busy === "connect"} onClick={onConnect}>
            {busy === "connect" ? "Connecting…" : "Connect wallet"}
          </button>
        )}
      </header>

      {!vault && (
        <>
          <form className="find" onSubmit={openVault}>
            <h1>Open a vault</h1>
            <p className="lede">Choose the network, then paste the vault address the organizers shared.</p>
            {CAN_CHOOSE_NETWORK && (
              <>
                <span className="label">Network</span>
                <NetworkPicker net={net} onChange={chooseNetwork} />
              </>
            )}
            <label htmlFor="vault-addr">Vault address</label>
            <input
              id="vault-addr"
              className="text-field"
              value={vaultInput}
              onChange={(e) => setVaultInput(e.target.value)}
              placeholder="0x…"
              spellCheck={false}
              autoComplete="off"
            />
            <button type="submit" className="btn btn-wax">
              Open vault
            </button>
            {net.testnet && <p className="hint left">{net.label} is a test network: its ETH has no value.</p>}
            {notice && <p className={`notice ${notice.kind}`}>{notice.text}</p>}
            {DEMO_BUTTON && (
              <div className="demo-cta">
                <p>No vault yet? Walk through every stage of a campaign with pretend funds.</p>
                <a className="btn-line" href="?demo">
                  Demo mode
                </a>
              </div>
            )}
          </form>
          <Connection key={net.key} conn={conn} onRpc={chooseRpc} />
        </>
      )}

      {vault && loadError && <p className="notice err">{loadError}</p>}
      {vault && !s && !loadError && <p className="loading">Loading vault…</p>}

      {vault && s && (
        <main>
          {trust === "unverified" && !DEMO && (
            <p className="notice warn">
              This page can't confirm the vault is genuine, because no vault factory is configured for {net.label}.
              Only contribute if you trust the link you followed.
            </p>
          )}
          <section className="hero">
            <Cipherfield mode={s.phase === Phase.Claimed ? "unsealed" : s.phase === Phase.Expired ? "dormant" : "sealed"} />
            <Seal phase={s.phase} fill={fill} />
          </section>

          <section className="tally">
            <p className="raised">
              <span className="num">{eth(s.phase === Phase.Claimed ? s.released : s.total)}</span>
              <span className="unit">ETH</span>
            </p>
            <p className="tally-sub">
              {s.phase === Phase.Open && (
                <>
                  raised of {eth(s.threshold)} ETH, <strong>{eth(s.threshold - s.total)} ETH to go</strong>
                </>
              )}
              {s.phase === Phase.Locked && <>raised, past the {eth(s.threshold)} ETH goal</>}
              {s.phase === Phase.Claimed && <>funded and released to {short(s.recipient)}</>}
              {s.phase === Phase.Expired && <>raised, but the key never came</>}
            </p>
          </section>

          <PhaseTrack phase={s.phase} />

          <section className="state" aria-live="polite">
            {s.phase === Phase.Open && (
              <>
                <h1>Open for contributions</h1>
                <p className="lede">
                  The collective's work is already out there, sealed. When the goal is reached and the organizer
                  collects, the key that opens all of it is published in the same transaction. Until then, you can
                  take your money back.
                </p>
              </>
            )}
            {s.phase === Phase.Locked && (
              <>
                <h1>Goal reached</h1>
                <p className="lede">
                  Withdrawals are paused while the organizer releases the key. If it isn't out by{" "}
                  {when(s.deadline)}, {roughTime(timeLeft)} from now, everyone can withdraw.
                </p>
              </>
            )}
            {s.phase === Phase.Claimed && (
              <>
                <h1>Unsealed</h1>
                <p className="lede">The key is public. Everything sealed to this vault opens with it, for everyone, starting now.</p>
              </>
            )}
            {s.phase === Phase.Expired && (
              <>
                <h1>The key wasn't released in time</h1>
                <p className="lede">The vault closed without unlocking. Everyone can withdraw what they put in.</p>
              </>
            )}
          </section>

          {(s.phase === Phase.Open || s.phase === Phase.Locked) && (
            <dl className="terms">
              <div>
                <dt>Funds go to</dt>
                <dd>
                  <code title={s.recipient}>{short(s.recipient)}</code>
                  <Copy text={s.recipient} label="Copy" />
                </dd>
              </div>
              <div>
                <dt>Key due</dt>
                <dd>{duration(s.claimWindow)} after the goal, or refunds</dd>
              </div>
            </dl>
          )}

          {notice && (
            <p className={`notice ${notice.kind}`} role="status">
              {notice.text}
            </p>
          )}

          {s.phase !== Phase.Claimed && (
            <section className="panel">
              {!account ? (
                <div className="connect-card">
                  <p>Connect a wallet to contribute or see your stake.</p>
                  <button type="button" className="btn btn-wax" disabled={busy === "connect"} onClick={onConnect}>
                    {busy === "connect" ? "Connecting…" : "Connect wallet"}
                  </button>
                </div>
              ) : (
                <>
                  {s.phase === Phase.Open && (
                    <form className="give" onSubmit={onContribute}>
                      <label htmlFor="amt">Contribution</label>
                      <div className="amount-field">
                        <input
                          id="amt"
                          inputMode="decimal"
                          autoComplete="off"
                          placeholder="0.00"
                          value={amountIn}
                          onChange={(e) => setAmountIn(e.target.value)}
                        />
                        <span aria-hidden="true">ETH</span>
                      </div>
                      <div className="chips" role="group" aria-label="Quick amounts">
                        {PRESETS.map((p) => (
                          <button key={p} type="button" className="chip" aria-pressed={amountIn === p} aria-label={`${p} ETH`} onClick={() => setAmountIn(p)}>
                            {p}
                          </button>
                        ))}
                      </div>
                      <button type="submit" className="btn btn-wax" disabled={!!busy}>
                        {busy === "contribute" ? "Contributing…" : wei ? `Contribute ${eth(wei)} ETH` : "Contribute"}
                      </button>
                      {wei !== null && <p className="hint">{shareHint(s, wei)}</p>}
                    </form>
                  )}

                  <div className="stake">
                    <div className="stake-text">
                      <span>Your stake</span>
                      <strong>{s.mine > 0n ? `${eth(s.mine)} ETH` : "Nothing yet"}</strong>
                    </div>
                    {s.mine > 0n && s.phase === Phase.Open && (
                      <button type="button" className="btn-line" onClick={onWithdraw} disabled={!!busy}>
                        {busy === "withdraw" ? "Withdrawing…" : "Withdraw"}
                      </button>
                    )}
                  </div>
                  {s.phase === Phase.Open && s.mine > 0n && s.total * 10n >= s.threshold * 9n && (
                    <p className="heads-up">
                      The vault is {Math.floor(ratio(s.total, s.threshold) * 100)}% funded and could lock with the next
                      contribution. Once it locks, your stake stays in until the key is released or the claim window
                      ends. If you might want your money back, withdraw now.
                    </p>
                  )}
                  {s.phase === Phase.Locked && s.mine > 0n && (
                    <p className="hint left">Locked until the key is released, or until {when(s.deadline)}.</p>
                  )}
                  {s.phase === Phase.Expired && s.mine > 0n && (
                    <button type="button" className="btn btn-wax" onClick={onWithdraw} disabled={!!busy}>
                      {busy === "withdraw" ? "Withdrawing…" : `Withdraw ${eth(s.mine)} ETH`}
                    </button>
                  )}
                </>
              )}
            </section>
          )}

          {s.phase === Phase.Claimed && (
            <section className="key-card">
              <h2>Decryption key</h2>
              <DecodedKey value={keyHex(s.revealedKey)} />
              <Copy text={keyHex(s.revealedKey)} label="Copy key" className="btn btn-wax" />
              <p>Open each sealed file with its metadata file:</p>
              <pre>vault-open open --secret {keyHex(s.revealedKey)} yourfile.meta.json</pre>
            </section>
          )}

          <details className="creators">
            <summary>Making something for this vault?</summary>
            <p>Seal your file to the campaign key. You don't need anything secret to do this.</p>
            <code className="mono-box">{s.campaignKey}</code>
            <div className="row-end">
              <Copy text={s.campaignKey} label="Copy campaign key" />
            </div>
            <pre>vault-seal seal --campaign-key {s.campaignKey} yourfile</pre>
            <p>
              This makes two files. Share <code>yourfile.enc</code> anywhere; it's the encrypted file. Share{" "}
              <code>yourfile.meta.json</code> with it; it holds the sealed key that opens it.
            </p>
          </details>
          {!DEMO && <Connection key={net.key} conn={conn} onRpc={chooseRpc} />}
        </main>
      )}
      {vault && !s && !DEMO && <Connection key={net.key} conn={conn} onRpc={chooseRpc} />}

      {DEMO && (
        <nav className="demo-bar" aria-label="Demo controls">
          <span>
            Demo vault with pretend funds
            {DEMO_BUTTON && (
              <>
                {" · "}
                <a href="?">Exit demo</a>
              </>
            )}
          </span>
          <div className="seg">
            {(
              [
                [Phase.Open, "Open"],
                [Phase.Locked, "Goal"],
                [Phase.Claimed, "Unsealed"],
                [Phase.Expired, "Expired"],
              ] as const
            ).map(([p, label]) => (
              <button
                key={label}
                type="button"
                aria-pressed={s?.phase === p}
                onClick={() => {
                  demo.setPhase(p);
                  setNotice(null);
                  refresh();
                }}
              >
                {label}
              </button>
            ))}
          </div>
        </nav>
      )}
    </div>
  );
}
