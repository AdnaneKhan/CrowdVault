//! Creator and coordinator tool: make the campaign key, and seal files to it.
//! Backers check and open sealed files with `vault-open`.

use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use vault_seal::{seal, zk, CampaignKey, CampaignSecret};

mod common;
use common::*;

#[derive(Parser)]
#[command(
    name = "vault-seal",
    version,
    about = "Seal files to a CrowdVault campaign key (creators), and make that key (coordinator). Backers use vault-open."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a campaign secret (coordinator only). Prints the public key
    /// values to pass to the contract constructor.
    Keygen {
        /// Where to write the secret. Keep this file offline.
        #[arg(long, default_value = "campaign.secret")]
        out: PathBuf,
        /// Overwrite an existing secret file.
        #[arg(long)]
        force: bool,
    },
    /// Print the public key for a secret file.
    Pubkey {
        /// The secret file written by keygen
        #[arg(long, default_value = "campaign.secret")]
        secret_file: PathBuf,
    },
    /// Seal a file: writes <file>.enc (share anywhere) and <file>.meta.json
    /// (the sealed key). Anyone can do this; no secret needed.
    Seal {
        /// Campaign public key (compressed or uncompressed SEC1 hex)
        #[arg(long)]
        campaign_key: String,
        input: PathBuf,
        /// Directory for the outputs (default: next to the input)
        #[arg(long)]
        out_dir: Option<PathBuf>,
        /// Also write <file>.proof: a zero-knowledge proof (about 1.5 KB) that
        /// the key this vault reveals opens the file to exactly its
        /// fingerprint. For small files.
        #[arg(long)]
        prove: bool,
        /// Largest file --prove accepts, in KiB
        #[arg(long, default_value_t = 64)]
        max_kib: u64,
    },
    /// Print a file's fingerprint, to publish for a proven file.
    Fingerprint { input: PathBuf },
}

impl Cmd {
    /// Every command except fingerprinting touches a secret.
    fn handles_secrets(&self) -> bool {
        !matches!(self, Cmd::Fingerprint { .. })
    }
}

fn main() -> Result<()> {
    harden_process();
    let cmd = Cli::parse().cmd;
    if cmd.handles_secrets() {
        warn_if_not_hardened();
    }
    match cmd {
        Cmd::Keygen { out, force } => {
            if out.exists() && !force {
                bail!("{} already exists; pass --force to overwrite", out.display());
            }
            let sk = CampaignSecret::generate();
            write_secret(&out, &sk.to_hex())?;
            print_pubkey(&sk.public());
            eprintln!(
                "\nSecret written to {}. Keep it offline and backed up: anyone who has it can open every sealed file before the goal is reached, and without it the vault can never unlock.",
                out.display()
            );
        }
        Cmd::Pubkey { secret_file } => {
            let sk = read_secret_file(&secret_file)?;
            print_pubkey(&sk.public());
        }
        Cmd::Seal { campaign_key, input, out_dir, prove, max_kib } => {
            let pk = CampaignKey::from_hex(&campaign_key).context("parsing --campaign-key")?;
            let name = input.file_name().and_then(|n| n.to_str()).context("input has no file name")?.to_string();
            let dir = out_dir.unwrap_or_else(|| input.parent().map(Path::to_path_buf).unwrap_or_default());
            fs::create_dir_all(&dir)?;
            let enc_path = dir.join(format!("{name}.enc"));
            let meta_path = dir.join(format!("{name}.meta.json"));

            if prove {
                let data = fs::read(&input).with_context(|| format!("reading {}", input.display()))?;
                eprintln!("Sealing {name} with a proof ({} bytes)…", data.len());
                let started = Instant::now();
                let sealed = zk::seal_and_prove(&pk, &name, &data, kib(max_kib)?)?;
                let proof_path = dir.join(format!("{name}.proof"));
                fs::write(&enc_path, &sealed.encrypted)?;
                fs::write(&meta_path, sealed.meta.to_json()?)?;
                fs::write(&proof_path, &sealed.proof)?;
                out!("Sealed {} with a proof", input.display());
                out!("  encrypted file: {}", enc_path.display());
                out!("  metadata:       {}", meta_path.display());
                out!("  proof:          {} ({} bytes)", proof_path.display(), sealed.proof.len());
                out!("  fingerprint:    {}", sealed.meta.fingerprint);
                out!("  {} gates, proved and self-checked in {:.1?}", sealed.gates, started.elapsed());
                return Ok(());
            }

            let reader = BufReader::new(File::open(&input).with_context(|| format!("reading {}", input.display()))?);
            let tmp = with_suffix(&enc_path, ".partial");
            let meta = {
                let mut w = BufWriter::new(File::create(&tmp)?);
                let m = seal(&pk, &name, reader, &mut w);
                drop(w);
                m.inspect_err(|_| {
                    let _ = fs::remove_file(&tmp);
                })?
            };
            fs::rename(&tmp, &enc_path)?;
            fs::write(&meta_path, meta.to_json()?)?;
            out!("Sealed {}", input.display());
            out!("  encrypted file: {}", enc_path.display());
            out!("  metadata:       {}", meta_path.display());
        }
        Cmd::Fingerprint { input } => fingerprint(&input)?,
    }
    Ok(())
}
