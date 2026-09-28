//! Backer tool: check sealed files against the vault's key before
//! contributing, and open them once the key is revealed. Creators seal files
//! with `vault-seal`.

use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use vault_seal::{open, verify, zk, CampaignKey, CampaignSecret};

mod common;
use common::*;

#[derive(Parser)]
#[command(
    name = "vault-open",
    version,
    about = "Check files sealed to a CrowdVault campaign, and open them once its key is revealed"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Check, with no secret, that the key this campaign reveals will open the
    /// file, and that the encrypted file matches its metadata.
    Verify {
        /// Campaign public key, taken from the vault itself (the vault page, or
        /// keyX/keyY on-chain), never from the metadata file
        #[arg(long)]
        campaign_key: String,
        /// The .meta.json file
        meta: PathBuf,
        /// The .enc file (default: next to the metadata)
        #[arg(long)]
        encrypted: Option<PathBuf>,
        /// The .proof file of a proven file (default: next to the metadata)
        #[arg(long)]
        proof: Option<PathBuf>,
        /// Largest proven file to check, in KiB. Protects against hostile
        /// files built to make verification run for hours.
        #[arg(long, default_value_t = 64)]
        max_kib: u64,
    },
    /// Decrypt with the revealed secret (from the contract's `revealedKey()`
    /// or the `Claimed` event).
    Open {
        /// Revealed secret, hex. Or use --secret-file.
        #[arg(long, conflicts_with = "secret_file")]
        secret: Option<String>,
        /// File holding the secret as hex (e.g. the coordinator's campaign.secret)
        #[arg(long)]
        secret_file: Option<PathBuf>,
        /// The .meta.json file
        meta: PathBuf,
        /// The .enc file (default: next to the metadata)
        #[arg(long)]
        encrypted: Option<PathBuf>,
        /// Directory for the opened file
        #[arg(long, default_value = ".")]
        out_dir: PathBuf,
    },
    /// Print a file's fingerprint, to compare against a proven file's metadata.
    Fingerprint { input: PathBuf },
}

fn main() -> Result<()> {
    harden_process();
    let cmd = Cli::parse().cmd;
    // Only opening touches a secret.
    if matches!(cmd, Cmd::Open { .. }) {
        warn_if_not_hardened();
    }
    match cmd {
        Cmd::Verify { campaign_key, meta, encrypted, proof, max_kib } => {
            let pk = CampaignKey::from_hex(&campaign_key).context("parsing --campaign-key")?;
            let enc = encrypted.unwrap_or_else(|| sibling(&meta, ".enc"));
            match read_meta(&meta)? {
                AnyMeta::Stream(m) => {
                    let f = BufReader::new(File::open(&enc).with_context(|| format!("reading {}", enc.display()))?);
                    verify(&m, &pk, Some(f))?;
                    out!("OK: {}", m.file_name);
                    out!("  The key this vault reveals will open it: the sealed key is valid and bound to this campaign.");
                    out!("  {} matches the metadata byte for byte.", enc.display());
                    out!("  Content is the creator's claim until opened: {} bytes, blake3 {}", m.plaintext_len, m.plaintext_blake3);
                }
                AnyMeta::Zk(m) => {
                    let proof_path = proof.unwrap_or_else(|| sibling(&meta, ".proof"));
                    let enc_bytes = fs::read(&enc).with_context(|| format!("reading {}", enc.display()))?;
                    let proof_bytes =
                        fs::read(&proof_path).with_context(|| format!("reading the proof {}", proof_path.display()))?;
                    zk::verify(&m, &pk, &enc_bytes, &proof_bytes, kib(max_kib)?)?;
                    out!("PROVEN: {}", m.file_name);
                    out!("  The key this vault reveals will open it to a {}-byte file with fingerprint", m.plaintext_len);
                    out!("  {}", m.fingerprint);
                    out!("  If that fingerprint was published for a work you trust, the file is exactly that work.");
                    out!("  Check a copy of the work with: vault-open fingerprint <file>");
                }
            }
        }
        Cmd::Open { secret, secret_file, meta, encrypted, out_dir } => {
            let sk = match (secret, secret_file) {
                (Some(s), _) => CampaignSecret::from_hex(&s)?,
                (None, Some(f)) => read_secret_file(&f)?,
                (None, None) => bail!("pass --secret or --secret-file"),
            };
            let any = read_meta(&meta)?;
            let enc = encrypted.unwrap_or_else(|| sibling(&meta, ".enc"));

            // Never trust the metadata's file name as a path.
            let name = Path::new(any.file_name())
                .file_name()
                .and_then(|n| n.to_str())
                .filter(|n| !n.is_empty() && *n != "." && *n != "..")
                .unwrap_or("opened.bin")
                .to_string();
            fs::create_dir_all(&out_dir)?;
            let dest = out_dir.join(&name);
            let tmp = with_suffix(&dest, ".partial");
            let result = match any {
                AnyMeta::Stream(m) => {
                    let reader = BufReader::new(File::open(&enc).with_context(|| format!("reading {}", enc.display()))?);
                    let mut w = BufWriter::new(File::create(&tmp)?);
                    let r = open(&m, &sk, reader, &mut w);
                    drop(w);
                    r
                }
                AnyMeta::Zk(m) => {
                    let bytes = fs::read(&enc).with_context(|| format!("reading {}", enc.display()))?;
                    zk::open(&m, &sk, &bytes).and_then(|pt| fs::write(&tmp, pt).map_err(Into::into))
                }
            };
            if let Err(e) = result {
                let _ = fs::remove_file(&tmp);
                return Err(e.into());
            }
            fs::rename(&tmp, &dest)?;
            out!("Opened {} -> {}", enc.display(), dest.display());
        }
        Cmd::Fingerprint { input } => fingerprint(&input)?,
    }
    Ok(())
}
