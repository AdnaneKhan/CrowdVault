use std::alloc::System;
use std::fs::{self, File};
use std::io::Write as _;
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use vault_seal::{open, seal, verify, zk, CampaignKey, CampaignSecret, Metadata};

/// Like println!, but a closed pipe (e.g. `vault-seal verify ... | head -1`)
/// ends output quietly instead of panicking.
macro_rules! out {
    ($($t:tt)*) => {{
        let _ = writeln!(std::io::stdout(), $($t)*);
    }};
}

#[derive(Parser)]
#[command(name = "vault-seal", version, about = "Seal files to a CrowdVault campaign key, and open them once it is revealed")]
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

enum AnyMeta {
    Stream(Metadata),
    Zk(zk::ZkMetadata),
}

impl AnyMeta {
    fn file_name(&self) -> &str {
        match self {
            AnyMeta::Stream(m) => &m.file_name,
            AnyMeta::Zk(m) => &m.file_name,
        }
    }
}

#[global_allocator]
static ALLOCATOR: vault_seal::WipeOnFree<System> = vault_seal::WipeOnFree(System);

/// Keep secrets out of core dumps, and out of reach of other processes of the
/// same user while the tool runs: on Linux by marking the process
/// non-dumpable (no ptrace, no /proc/<pid>/mem), on macOS by refusing debugger
/// attachment. macOS also exposes memory through the task port, which the
/// hardened runtime closes (see `warn_if_not_hardened`).
fn harden_process() {
    #[cfg(unix)]
    unsafe {
        let none = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &none);
    }
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
    #[cfg(target_os = "macos")]
    unsafe {
        // From here on no debugger can attach. A process already running under
        // a debugger is ended by this call, so the tool can't be debugged on macOS.
        libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0);
    }
}

/// On macOS, a program with debugger rights can read another's memory through
/// its task port without attaching, unless the binary is signed with the
/// hardened runtime. Before handling secrets, say so if this build isn't.
#[cfg(target_os = "macos")]
fn warn_if_not_hardened() {
    extern "C" {
        // <sys/codesign.h>: a process may read its own code-signing flags.
        fn csops(pid: libc::pid_t, ops: libc::c_uint, useraddr: *mut libc::c_void, usersize: libc::size_t) -> libc::c_int;
    }
    const CS_OPS_STATUS: libc::c_uint = 0;
    const CS_RUNTIME: u32 = 0x0001_0000;
    let mut flags: u32 = 0;
    let size = std::mem::size_of::<u32>();
    let read = unsafe { csops(libc::getpid(), CS_OPS_STATUS, (&mut flags as *mut u32).cast(), size) } == 0;
    if read && flags & CS_RUNTIME == 0 {
        let exe = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_else(|_| "vault-seal".into());
        eprintln!(
            "note: this build isn't signed with the hardened runtime, so a program with debugger rights could read its memory. Sign it once after each build:\n  codesign --force --options runtime --sign - \"{exe}\"\n"
        );
    }
}

#[cfg(not(target_os = "macos"))]
fn warn_if_not_hardened() {}

impl Cmd {
    /// Every command except checking and fingerprinting touches a secret.
    fn handles_secrets(&self) -> bool {
        !matches!(self, Cmd::Verify { .. } | Cmd::Fingerprint { .. })
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
                    out!("  Check a copy of the work with: vault-seal fingerprint <file>");
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
        Cmd::Fingerprint { input } => {
            let data = fs::read(&input).with_context(|| format!("reading {}", input.display()))?;
            out!("{}", zk::fingerprint_hex(&data));
        }
    }
    Ok(())
}

fn kib(v: u64) -> Result<u64> {
    v.checked_mul(1024).context("--max-kib is too large")
}

fn read_meta(p: &Path) -> Result<AnyMeta> {
    let s = fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?;
    let v: serde_json::Value = serde_json::from_str(&s).context("metadata is not valid JSON")?;
    Ok(match v.get("format").and_then(|f| f.as_str()) {
        Some(zk::FORMAT) => AnyMeta::Zk(zk::ZkMetadata::from_json(&s)?),
        _ => AnyMeta::Stream(Metadata::from_json(&s)?),
    })
}

/// `name.meta.json` -> `name.enc` / `name.proof`
fn sibling(meta: &Path, ext: &str) -> PathBuf {
    let s = meta.to_string_lossy();
    match s.strip_suffix(".meta.json") {
        Some(base) => PathBuf::from(format!("{base}{ext}")),
        None => with_suffix(meta, ext),
    }
}

fn with_suffix(p: &Path, suffix: &str) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

fn print_pubkey(pk: &CampaignKey) {
    let (x, y) = pk.xy_hex();
    out!("campaign key (share with creators): {}", pk.compressed_hex());
    out!("KEY_X={x}");
    out!("KEY_Y={y}");
    out!("keyAddress (contract check): {}", pk.eth_address());
}

fn read_secret_file(p: &Path) -> Result<CampaignSecret> {
    let s = fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?;
    Ok(CampaignSecret::from_hex(&s)?)
}

fn write_secret(p: &Path, hex: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(p)?;
        f.write_all(hex.as_bytes())?;
    }
    #[cfg(not(unix))]
    fs::write(p, hex)?;
    Ok(())
}

