# Coordinator guide

You run the campaign. You create the campaign key, deploy the vault, give creators what they need, and release the key once the goal is reached. This guide takes you from nothing to an unlocked vault.

Every command here is exercised by `scripts/e2e.sh` on a local chain.

## What you need

- A computer you trust to hold the campaign secret, ideally one you can keep offline between steps.
- Rust, to build `vault-seal` (and `vault-open`, which backers and creators use to check and open files). Foundry (`forge` and `cast`), to deploy and talk to the vault. Node.js 18 or later, only if you host the vault page yourself.
- An RPC URL for your chain, from a provider or your own node.
- A deployer account with ETH for gas. A first deployment uses about 3.1 million gas; [Gas and cost](deploying.md#gas-and-cost) turns that into ETH.
- A recipient address, where the money goes. It can be a multisig.
- Your numbers: the goal, and how long you'll have to claim once it's reached.

## 1. Install the tools

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh     # Rust
curl -L https://foundry.paradigm.xyz | bash && foundryup            # Foundry
```

Building the tools needs a C toolchain, which Rust's installer already asks for: Xcode command-line tools on macOS, build-essential on Linux, Visual Studio Build Tools on Windows.

From the root of this repo:

```bash
cargo install --path vault-seal      # puts vault-seal and vault-open on your PATH
vault-seal --help
cd contracts && forge test           # optional: every test should pass
```

Or skip building: download both tools ready to run, as described under [Prebuilt binaries](../README.md#prebuilt-binaries). The macOS downloads are already signed, so the next step isn't needed for them.

If you built the tools yourself on macOS, also sign both with the hardened runtime, so no other program can read their memory while they hold keys. Rebuilding removes the signature, so repeat this after each build; each tool reminds you if its build isn't signed.

```bash
codesign --force --options runtime --sign - "$(which vault-seal)"
codesign --force --options runtime --sign - "$(which vault-open)"
```

Put your deployer key in Foundry's encrypted keystore, so it never appears in your shell history:

```bash
cast wallet import deployer --interactive
```

## 2. Create the campaign key

```bash
vault-seal keygen --out campaign.secret
```

It prints:

```text
campaign key (share with creators): 03ab…     short form of the public key
KEY_X=0x…                                      goes into the deploy step
KEY_Y=0x…                                      goes into the deploy step
keyAddress (contract check): 0x…               used to check the deployed vault
```

`campaign.secret` holds the secret as hex, readable only by you. Guard it, because it can go wrong two ways:

- **If it leaks,** anyone can open every sealed file before the goal is reached. The money stays safe: the contract only ever pays the fixed recipient, and only after the goal.
- **If you lose it,** the vault can never unlock. Once the goal is reached, the claim window runs out and backers get refunds.

Make at least one offline backup, on paper or an encrypted drive. Reprint the public values at any time with `vault-seal pubkey --secret-file campaign.secret`.

Use each key for one campaign. Once a key has been revealed, everything sealed to it is open.

## 3. Choose the settings

| Setting | Meaning | How to get it |
| --- | --- | --- |
| `RECIPIENT` | Where the money goes | An ordinary account or a multisig such as Safe. The deployment sends it 1 wei and fails if it can't accept ETH. |
| `THRESHOLD_WEI` | The goal, in wei | `cast to-wei 10 ether` gives 10 ETH in wei |
| `CLAIM_WINDOW_SECONDS` | How long you have to claim once the goal is reached | At most 30 days (2,592,000), enforced by the contract. Two days is 172,800. |
| `KEY_X`, `KEY_Y` | The campaign public key | From `keygen` |

These are permanent. The contract has no owner and no admin functions: nobody, including you, can change the settings, pause the vault or take money out early. If you get something wrong, you deploy a new vault.

The 30-day cap protects backers: once the goal is reached, their money can never be frozen longer than your window.

## 4. Deploy

Do a full run on a testnet such as Sepolia first, with a tiny goal and a short window: deploy, contribute, claim, open.

**[Deploying the contracts](deploying.md)** covers this step in full: testnet and mainnet one after the other, gas and cost estimates, hardware wallets, and what to do if a deployment is interrupted. The short version follows.

Vaults are created through a factory, which records which addresses are genuine vaults; the vault page only shows those. The first deployment creates the factory. Keep its address and pass it as `FACTORY` for every later vault, so they all share one factory.

```bash
cd contracts
export RPC_URL=https://…
export RECIPIENT=0x…
export THRESHOLD_WEI=$(cast to-wei 10 ether)
export CLAIM_WINDOW_SECONDS=172800
export KEY_X=0x…          # from keygen
export KEY_Y=0x…          # from keygen
# export FACTORY=0x…      # your factory, after the first deployment

forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast \
  --account deployer --sender 0xYourDeployerAddress
```

It prints `CrowdVaultFactory at 0x…` and `CrowdVault deployed at 0x…`. The deployment also sends the recipient 1 wei, to prove it can accept the payout. Keep both addresses:

```bash
export FACTORY=0x…
export VAULT=0x…
```

Check that the vault holds your key and that the factory recognizes it:

```bash
cast call $VAULT "keyAddress()(address)" --rpc-url $RPC_URL
cast call $FACTORY "isVault(address)(bool)" $VAULT --rpc-url $RPC_URL     # true
```

The key address must match the `keyAddress` line from `keygen`, ignoring upper and lower case. If it doesn't, stop and deploy again.

Optionally, publish the source on Etherscan so backers can read the code: see [Publishing the source](deploying.md#publishing-the-source).

## 5. Put the vault page online

The page in `web/` is a static site with no server. Backers use it to contribute and withdraw, and it shows the key once it's released. You have two ways to host it.

**GitHub Pages, from a fork of this repo (easiest).** Every push to `main` publishes the page with `.github/workflows/pages.yml`. Visitors choose Ethereum or the Sepolia testnet, paste the vault address, or try the demo. It reads the chain through free public RPCs, so backers can see the vault before they connect a wallet.

1. Fork the repo. In the fork, open **Settings → Pages** and set **Source** to **GitHub Actions**.
2. So the page can tell your vaults from lookalikes, add your factory addresses under **Settings → Secrets and variables → Actions → Variables**: `FACTORY_MAINNET` and `FACTORY_SEPOLIA`. Without them, the page warns that it can't confirm a vault is genuine.
3. Run the **Pages** workflow from the **Actions** tab, or push to `main`.

The page appears at `https://<your-user>.github.io/<repo>/`. Share a link that opens your vault directly:

```text
https://<your-user>.github.io/<repo>/?network=mainnet&vault=0x…
```

Use `network=sepolia` for a testnet vault.

**Any static host, for one chain.** Build the page yourself:

```bash
cd web
npm install
cp .env.example .env
```

Edit `.env`:

- `VITE_CHAIN_ID`: the chain your vault is on, for example 1 for Ethereum or 8453 for Base. The page then serves only that chain: it refuses to send transactions on any other network and asks the wallet to switch. Leave it empty to offer Ethereum and Sepolia, as on GitHub Pages.
- `VITE_FACTORY_ADDRESS`: your factory. The page only shows vaults it created, so a lookalike contract at a phishing link is refused. Without it, the page warns that it can't confirm the vault is genuine. (Without `VITE_CHAIN_ID`, use `VITE_FACTORY_MAINNET` and `VITE_FACTORY_SEPOLIA` instead.)
- `VITE_VAULT_ADDRESS`: your vault, so the page opens straight to it. Without it, visitors paste the address or use `?vault=0x…` in the link.
- `VITE_RPC_URL`: lets visitors without a wallet see the vault. It ends up in the public page, so use a public endpoint or a key restricted to your domain. Ethereum and Sepolia already have public defaults.

Then:

```bash
npm run build
```

Upload `web/dist/` to any static host, such as Netlify, Vercel, Cloudflare Pages or IPFS. To preview first, run `npm run dev`; on the dev server, adding `?demo` shows a pretend vault you can step through every state of. Set `VITE_DEMO_BUTTON=1` to offer the same demo on your page. `npm run build:demo` makes a separate single-file demo page.

Visitors can switch to their own RPC under **Connection** at the bottom of the page. It's saved in their browser only.

## 6. Brief your creators

Send each creator:

- the vault address and the page link,
- `docs/creators.md` from this repo,
- how you'll collect their sealed files, and a date to have them in by.

Creators should take the campaign key from the vault page or the chain, not from a chat message. That protects everyone from a key swapped in transit.

Collect each creator's `.sealed` files (one per work; a proven file carries its proof inside), and publish a list of what's sealed, with links, so backers can check it before they contribute.

Proofs are optional and suit small files (up to 64 KB by default). A proof lets backers confirm, before paying, that a file opens to exactly the work with a given fingerprint. That's strongest when someone backers trust has seen the work privately, run `vault-seal fingerprint` on it, and published the fingerprint. Consider asking creators of small pieces to seal with a proof, and mark proven files in your list.

Files are sealed to the key, not to the vault address. If you redeploy with the same key, say to fix the goal, existing sealed files still work. If you redeploy with a new key, everything must be sealed again.

## 7. During the campaign

Watch the vault page, or ask the chain directly:

```bash
cast call $VAULT "phase()(uint8)" --rpc-url $RPC_URL
cast from-wei "$(cast call $VAULT 'totalContributed()(uint256)' --rpc-url $RPC_URL | awk '{print $1}')"
cast call $VAULT "deadline()(uint256)" --rpc-url $RPC_URL    # unix time; 0 until the goal is reached
date +%s                                                     # now, to compare
```

The phases:

- **0, Open.** Backers contribute and can withdraw freely. There's no deadline in this phase and nothing for you to do.
- **1, Locked.** The goal was reached. Withdrawals are frozen and the claim window is running.
- **2, Claimed.** You released the key and the money went to the recipient.
- **3, Expired.** The window passed without a claim. Backers withdraw their money.

## 8. Release the key

The vault locks in the same transaction that reaches the goal, and the claim window starts then. Claim early in the window.

First check the secret, locally, without sending it anywhere:

```bash
vault-seal pubkey --secret-file campaign.secret           # note its keyAddress
cast call $VAULT "keyAddress()(address)" --rpc-url $RPC_URL
```

The two must match. Don't use the contract's `isCampaignSecret` function for this check: calling it hands the secret to your RPC provider before you mean to reveal it.

Then claim:

```bash
cast send $VAULT "claim(uint256)" "$(cat campaign.secret)" --rpc-url $RPC_URL --account deployer
```

Any account can send the claim, because the money can only go to the recipient. Once the transaction is sent, the secret is public, even before it's mined. That's expected, and no one can redirect the funds.

Confirm it worked:

```bash
cast call $VAULT "phase()(uint8)" --rpc-url $RPC_URL           # 2
cast call $VAULT "revealedKey()(uint256)" --rpc-url $RPC_URL   # the key, now public
cast call $VAULT "releasedAmount()(uint256)" --rpc-url $RPC_URL # the whole pot, paid to the recipient
```

**Why claim early:** a claim that lands after the window fails, but its calldata, including the secret, is still published on-chain. Backers would then get the files and their refunds.

**If the recipient rejected the payment** (the deployment checks it can accept ETH, but a contract recipient can change its mind), the claim still stands and the money waits in the vault:

```bash
cast call $VAULT "pendingPayout()(uint256)" --rpc-url $RPC_URL      # non-zero means it's waiting
cast send $VAULT "releasePayout()" --rpc-url $RPC_URL --account deployer
```

Anyone can call `releasePayout()`. It retries sending to the recipient, and it also sweeps any ETH that was force-sent to the vault.

## 9. After the unlock

The key is on-chain and on the vault page. Announce it and point people to the "After the unlock" section of `docs/creators.md`, which shows how to open files. The secret is public now, so `campaign.secret` no longer needs protecting.

## If something goes wrong

- **The goal is never reached.** The vault stays Open indefinitely and backers can withdraw at any time. Tell them the campaign is over.
- **You miss the claim window.** The vault expires and everyone withdraws. It can't be reopened. The window is at most 30 days, so backers are never frozen longer than that. You can deploy a new vault with the same key only if the secret never went on-chain; a late, failed claim publishes it.
- **The secret leaks early.** Anyone can open the files early. The money is safe, but there's no way to take the leak back.
- **You lose the secret.** The vault can never unlock. Once the goal is reached, it expires and backers get refunds.
- **A setting is wrong.** Deploy a new vault and ask backers to withdraw from the old one while it's still Open. If it has already locked, they have to wait for it to expire.

## Checklist

- [ ] Tools installed, and `vault-seal --help` works
- [ ] `campaign.secret` generated and backed up offline
- [ ] Settings chosen
- [ ] Full test run on a testnet ([Deploying the contracts](deploying.md))
- [ ] Vault deployed through the factory, its `keyAddress` matches, and `isVault` is true
- [ ] Vault page online, and it recognizes your vault as genuine (no warning)
- [ ] Creators briefed, and the list of sealed files published
- [ ] Claimed early in the window, and the recipient paid
- [ ] Key announced
