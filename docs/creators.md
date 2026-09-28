# Creator guide

You make something, seal it to the campaign key, and share it. You never handle a secret, you don't need a wallet, and sealing works offline.

## What you need

- `vault-seal` to seal, and `vault-open` to check and open (install both below)
- The vault address, from the campaign coordinator
- Your files, of any type and any size

## 1. Install the tools

Install Rust, then build `vault-seal` and `vault-open` from this repo. This works on macOS, Linux and Windows. Building needs a C toolchain, which Rust's installer already asks for: Xcode command-line tools on macOS, build-essential on Linux, Visual Studio Build Tools on Windows.

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
cargo install --path vault-seal      # run from the root of this repo; installs both tools
vault-seal --help
```

On macOS, also sign both tools with the hardened runtime, so no other program can read its memory while it holds keys. Rebuilding removes the signature, so repeat this after each build; each tool reminds you if its build isn't signed.

```bash
codesign --force --options runtime --sign - "$(which vault-seal)"
codesign --force --options runtime --sign - "$(which vault-open)"
```

## 2. Get the campaign key

Always take the key from the vault itself, never from a message or from someone else's files. A file sealed to the wrong key can never be opened.

**From the vault page:** open "Making something for this vault?" and copy the campaign key.

**From the chain**, with Foundry installed:

```bash
export VAULT=0x…            # the vault address
export RPC_URL=https://…    # any RPC endpoint for the vault's chain
KX=$(cast call $VAULT "keyX()" --rpc-url $RPC_URL)
KY=$(cast call $VAULT "keyY()" --rpc-url $RPC_URL)
export CAMPAIGN_KEY=04${KX#0x}${KY#0x}
```

The page shows a short form of the key (starting 02 or 03), and the chain gives a long form (starting 04). Both tools accept either.

## 3. Seal your file

```bash
vault-seal seal --campaign-key $CAMPAIGN_KEY artwork.png --out-dir sealed
```

This makes two files:

| File | What it is | Share it? |
| --- | --- | --- |
| `sealed/artwork.png.enc` | Your file, encrypted | Yes, anywhere |
| `sealed/artwork.png.meta.json` | The sealed key, plus the file's name, size and fingerprint | Yes, always together with the `.enc` |

Neither file contains anything secret, and both are needed to open it. The encrypted file is about the same size as the original. Files of any size stream through, so full-length video is fine.

To seal a whole folder:

```bash
for f in art/*; do vault-seal seal --campaign-key $CAMPAIGN_KEY "$f" --out-dir sealed; done
```

**What stays public:** the metadata shows the file's name, its exact size and its BLAKE3 hash. To keep the name private, rename the file before sealing, to something like `drop-01.mp4`. The name is sealed in and can't be changed afterwards. And if the same file is available elsewhere, anyone can match its hash (`b3sum` computes it).

## 4. Check before you share

```bash
vault-open verify --campaign-key $CAMPAIGN_KEY sealed/artwork.png.meta.json
```

`OK` means the key this vault reveals will open your file, and the `.enc` file matches its metadata byte for byte. Keep your original file: nobody can open the sealed copy before the unlock, including you.

## 5. Share

- Upload both files anywhere that works for you: your website, IPFS, a torrent, cloud storage, Discord.
- Send the coordinator both links, so your work appears on the campaign's list.
- Keep each pair together. `vault-open open` looks for the `.enc` file next to the `.meta.json` with the matching name. You can rename both on disk; whoever opens them then points to the `.enc` with `--encrypted`.
- Never edit the values inside a `.meta.json`. They are sealed in, and any change stops the file from opening.

## Optional: seal with a proof (small files)

For files up to 64 KB, you can add a zero-knowledge proof. Without one, backers can confirm the vault's key will open your file, but they take your word for what's inside. With one, they can confirm, before paying, that the key will open it to a file with the exact fingerprint you committed to, without learning anything about the content.

```bash
vault-seal seal --campaign-key $CAMPAIGN_KEY poem.txt --out-dir sealed --prove
```

This makes three files: `poem.txt.enc`, `poem.txt.meta.json`, and `poem.txt.proof`, about 1.5 KB. Share all three together. Proving takes a second or two for a few kilobytes, and about 40 seconds near the 64 KB limit on a single core; several cores make it several times faster. The first proof on a machine also computes and caches some fixed data, which takes a few seconds more. Raise the limit with `--max-kib`, but proving time grows with size.

The metadata of a proven file carries a **fingerprint** instead of a BLAKE3 hash. Anyone holding a copy of the original can compute it and compare:

```bash
vault-seal fingerprint poem.txt
```

That is what makes the proof useful: if a reviewer, a publisher or you yourself post the fingerprint of the real work somewhere public, backers know the sealed file is exactly that work, not merely *some* file with a matching fingerprint. Without a published fingerprint, the proof only guarantees that the file opens and that you can't swap it afterwards. The fingerprint reveals nothing about the content, but anyone who already has a copy of the same file can confirm the match.

Proven files work everywhere ordinary ones do: `verify` checks the proof automatically when it finds one, and `open` works the same way. `verify` refuses proven files over 64 KB unless given `--max-kib`, because a hostile file could otherwise make checking take hours.

## 6. What backers can and can't check

Before the unlock, anyone can confirm with `verify` that the vault's key will open your file. For an ordinary sealed file, they can't see what's inside, so they're trusting you that it's what you promised. For a proven file, `verify` also proves it opens to a file with the committed fingerprint, which is exactly the work if that fingerprint was published for it. After the unlock, if a file doesn't match the fingerprint in its metadata, `vault-open` reports it as the creator's fault, and anyone can reproduce that.

## 7. After the unlock

The key appears on the vault page, with a copy button. You can also read it from the chain:

```bash
KEY=$(cast to-hex "$(cast call $VAULT 'revealedKey()(uint256)' --rpc-url $RPC_URL | awk '{print $1}')")
vault-open open --secret $KEY sealed/artwork.png.meta.json --out-dir opened
```

Before the unlock, `revealedKey()` returns 0.

If opening fails, the message says why:

| Message | What it means |
| --- | --- |
| secret does not match the campaign key | The key is from a different vault, or it was copied wrong |
| encrypted file or its metadata was altered, corrupted or reordered | One of the two files was damaged or changed. Download both again. |
| encrypted file is truncated | The download was cut off |
| decrypted file does not match the hash the creator committed to | The creator sealed something other than what the metadata promised |
| decrypted file does not match the fingerprint the creator committed to | The same, for a proven file that has no valid proof. A proven file whose proof verified always opens. |

## Questions

**Can I change a file after sealing it?** Seal the new version and share the new pair, and ask the coordinator to update the list. The old pair still opens too.

**Can I offer the same work in two campaigns?** Yes, but seal it separately for each campaign's key.

**Do I need a wallet or ETH?** No. You only need the campaign key.

**What if I lose the `.meta.json`?** The `.enc` can't be opened without it, so keep both.

**Does sealing leave keys behind?** No. Each seal draws a fresh random key, and `vault-seal` wipes it from memory as soon as the file is encrypted, along with everything derived from it. It also keeps keys out of swap where the system allows, and on macOS and Linux out of core dumps and out of other programs' reach while it runs (on macOS, once the tool is signed as in step 1). A test scans the tool's entire memory after sealing to confirm nothing remains. Your plaintext file is yours to manage: delete it separately if it shouldn't stay on the machine. Pass the campaign secret with `--secret-file` rather than `--secret`, because command-line arguments can end up in your shell history.

**Should I add a proof?** For small work where trust matters, yes. It costs a few seconds and 1.5 KB. For large files like video, it isn't practical yet, so seal those the ordinary way.

**Can I test-open my sealed file?** Not before the unlock. Nobody can, which is the point. Keep your original.
