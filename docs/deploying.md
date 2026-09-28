# Deploying the contracts

How to put a CrowdVault on a testnet and then on Ethereum mainnet, and what it costs. This expands step 4 of the [coordinator guide](coordinator.md); do steps 1 to 3 there first, so you have Foundry installed, a deployer account in Foundry's keystore, a campaign key, and your settings.

**Always do a full run on a testnet first.** Deploying to mainnet is permanent: the contract has no owner and no admin functions, so a wrong setting means deploying a new vault.

## What gets deployed

- **The factory** (`CrowdVaultFactory`), once. It creates vaults and records which addresses are genuine; the vault page only shows vaults it created. Deploy one per chain and reuse it.
- **A vault** (`CrowdVault`), once per campaign, created through the factory.

`script/Deploy.s.sol` does both on the first run. Pass `FACTORY=0x…` on later runs and it only creates the vault.

## Gas and cost

Measured on a local chain with Foundry 1.8.3 and this repo's contracts. The gas amount of each transaction doesn't depend on the chain, only the gas price does.

| Transaction | Who pays | Gas |
| --- | --- | --- |
| First deployment: factory + vault | Coordinator | about 3,130,000 (1,857,000 + 1,271,000) |
| Each later vault, reusing the factory | Coordinator | about 1,246,000 |
| `claim` (pays out and reveals the key) | Coordinator, or anyone | about 113,000 |
| First contribution from a backer | Backer | about 75,000 |
| The contribution that reaches the goal | Backer | about 96,000 |
| Adding to an earlier contribution | Backer | about 40,000 |
| `withdraw` | Backer | about 40,000 |

**Cost = gas × gas price.** At a few example gas prices:

| Transaction | 0.5 gwei | 2 gwei | 10 gwei | 50 gwei |
| --- | --- | --- | --- | --- |
| First deployment | 0.0016 ETH | 0.0063 ETH | 0.031 ETH | 0.16 ETH |
| Later vault | 0.0006 ETH | 0.0025 ETH | 0.012 ETH | 0.062 ETH |
| `claim` | 0.00006 ETH | 0.0002 ETH | 0.0011 ETH | 0.0057 ETH |
| Backer's first contribution | 0.00004 ETH | 0.00015 ETH | 0.00075 ETH | 0.0037 ETH |

Mainnet gas prices move a lot, often within a day. Check the current price before you deploy:

```bash
cast to-unit $(cast gas-price --rpc-url $RPC_URL) gwei       # current gas price, in gwei
```

When gas is expensive, waiting for a quieter time (weekends and nights in the US and Europe are often cheaper) can cut the cost several times over. On testnets gas is free: you use test ETH from a faucet.

**How much ETH the deployer needs:** the simulation step below prints it as `Estimated amount required`. Foundry adds a safety margin (it estimates about 4,170,000 gas for a first deployment) and prices it at up to twice the current base fee, and the account must hold that much, plus 1 wei that is forwarded to the recipient. Hold at least **twice the expected cost** so a price rise during deployment doesn't stall it. Unused gas is not charged.

Keep enough in the coordinator's account for the `claim` later, too. It must land inside the claim window, so don't let a gas spike be the reason you miss it.

## Before you start

Set up your shell once per session. Everything below runs from `contracts/`.

```bash
cd contracts
export KEY_X=0x…            # from vault-seal keygen
export KEY_Y=0x…            # from vault-seal keygen
export RECIPIENT=0x…
export THRESHOLD_WEI=$(cast to-wei 10 ether)
export CLAIM_WINDOW_SECONDS=172800
export DEPLOYER=0x…         # the address of your keystore account: cast wallet address --account deployer
export ETHERSCAN_API_KEY=…  # optional, to publish the source; one key works for mainnet and Sepolia
```

An RPC URL comes from a provider such as Alchemy, Infura or QuickNode (free tiers are enough), or from your own node. Public endpoints work for a test but can be slow or rate-limited.

## 1. Deploy to the Sepolia testnet

Sepolia is Ethereum's testnet for applications (chain ID 11155111). Its ETH has no value.

**Get test ETH.** Search for a "Sepolia faucet"; providers such as Alchemy and Google Cloud run free ones. Some ask for a small mainnet balance or a login to stop abuse. 0.05 Sepolia ETH is plenty for the deployment and a few test transactions.

```bash
export RPC_URL=https://…your Sepolia RPC…
cast chain-id --rpc-url $RPC_URL                                      # 11155111
cast balance $DEPLOYER --ether --rpc-url $RPC_URL                     # your test ETH
```

**Use test settings.** A tiny goal and a short window let you run the whole campaign in minutes:

```bash
export THRESHOLD_WEI=$(cast to-wei 0.001 ether)
export CLAIM_WINDOW_SECONDS=3600
```

**Simulate first.** Without `--broadcast`, nothing is sent: Foundry runs the deployment against the live chain and prints the addresses it would create, the gas, and `Estimated amount required` in ETH.

```bash
forge script script/Deploy.s.sol --rpc-url $RPC_URL --account deployer --sender $DEPLOYER
```

**Deploy.** Add `--broadcast`, and `--verify` if you set `ETHERSCAN_API_KEY`:

```bash
forge script script/Deploy.s.sol --rpc-url $RPC_URL --account deployer --sender $DEPLOYER \
  --broadcast --verify
```

It asks for your keystore password, then prints:

```text
CrowdVaultFactory at 0x…
CrowdVault deployed at 0x…
```

Keep both, and check the vault (the coordinator guide explains each check):

```bash
export FACTORY=0x…
export VAULT=0x…
cast call $VAULT "keyAddress()(address)" --rpc-url $RPC_URL              # matches keyAddress from keygen
cast call $FACTORY "isVault(address)(bool)" $VAULT --rpc-url $RPC_URL    # true
```

The contracts appear on [sepolia.etherscan.io](https://sepolia.etherscan.io). Now run the rest of the campaign there: point a local vault page at it (`VITE_CHAIN_ID=11155111`), seal a file, contribute from a second account, claim, and open the file. The [coordinator guide](coordinator.md) walks through each step. If anything surprises you, fix it here, not on mainnet.

## 2. Deploy to Ethereum mainnet

The same steps, with real money. Go through this list first:

- [ ] The full testnet run worked, start to finish.
- [ ] Your real settings are exported: the real `THRESHOLD_WEI` and `CLAIM_WINDOW_SECONDS`, not the test ones. Print them and read them again.
- [ ] `RECIPIENT` is right. A multisig such as Safe is a good choice; make sure it exists **on mainnet**, not only on another chain.
- [ ] `KEY_X` and `KEY_Y` are from the campaign key you'll really use, and `campaign.secret` is backed up offline.
- [ ] `FACTORY` is unset for the first mainnet deployment (`unset FACTORY`). A testnet factory's address means nothing on mainnet.
- [ ] The deployer holds enough ETH (see [Gas and cost](#gas-and-cost)).

For the deployer, prefer a hardware wallet: replace `--account deployer` with `--ledger` or `--trezor`, and `--sender` with the device's address.

```bash
export RPC_URL=https://…your mainnet RPC…
cast chain-id --rpc-url $RPC_URL                                      # 1
cast balance $DEPLOYER --ether --rpc-url $RPC_URL
env | grep -E '^(RECIPIENT|THRESHOLD_WEI|CLAIM_WINDOW_SECONDS|KEY_X|KEY_Y|FACTORY)='

# Simulate: check the settings and the estimated cost it prints
forge script script/Deploy.s.sol --rpc-url $RPC_URL --account deployer --sender $DEPLOYER

# Deploy
forge script script/Deploy.s.sol --rpc-url $RPC_URL --account deployer --sender $DEPLOYER \
  --broadcast --verify
```

Then run the same checks as on the testnet, and look the vault up on [etherscan.io](https://etherscan.io).

**If the deployment is interrupted** (a dropped connection, or gas rising above what you offered), don't start over: that could create a second factory. Run the same command with `--resume` added. Foundry keeps a record of what it sent in `contracts/broadcast/`.

To cap what you pay per unit of gas, add `--with-gas-price 5gwei` (or any amount). If the network price rises above it, the transactions wait until it comes back down.

## Publishing the source

Publishing the source on Etherscan lets backers read the code they're trusting. `--verify` does it for the factory during deployment. To do it afterwards, or on another explorer:

```bash
forge verify-contract $FACTORY src/CrowdVaultFactory.sol:CrowdVaultFactory --chain mainnet   # or sepolia
```

Etherscan usually matches vaults to the verified code on its own. If a vault still shows as unverified, verify it with its settings:

```bash
forge verify-contract $VAULT src/CrowdVault.sol:CrowdVault --chain mainnet \
  --constructor-args $(cast abi-encode "constructor(address,uint256,uint256,uint256,uint256)" \
    $RECIPIENT $THRESHOLD_WEI $CLAIM_WINDOW_SECONDS $KEY_X $KEY_Y)
```

## Later campaigns

Reuse your mainnet factory, so every vault shows on the same page:

```bash
export FACTORY=0x…your mainnet factory…
forge script script/Deploy.s.sol --rpc-url $RPC_URL --account deployer --sender $DEPLOYER --broadcast
```

This costs about 1,246,000 gas, roughly 40% of a first deployment. Use a new campaign key for each campaign.

## Other chains

The same commands work on any EVM chain Foundry supports, including layer 2s such as Base, Optimism and Arbitrum, where the same gas usually costs a small fraction of mainnet. Deploy a separate factory on each chain, and set the page's `VITE_CHAIN_ID` to match. Backers need ETH on that chain to take part.
