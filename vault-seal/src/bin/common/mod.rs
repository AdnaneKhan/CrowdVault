//! Shared by the `vault-seal` (creator) and `vault-open` (backer) binaries.
//! Each binary uses only part of it.
#![allow(dead_code)]

use std::alloc::System;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use vault_seal::{zk, CampaignKey, CampaignSecret, Metadata};

/// Like println!, but a closed pipe (e.g. `vault-open verify ... | head -1`)
/// ends output quietly instead of panicking.
macro_rules! out {
    ($($t:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stdout(), $($t)*);
    }};
}
pub(crate) use out;

#[global_allocator]
static ALLOCATOR: vault_seal::WipeOnFree<System> = vault_seal::WipeOnFree(System);

pub enum AnyMeta {
    Stream(Metadata),
    Zk(zk::ZkMetadata),
}

impl AnyMeta {
    pub fn file_name(&self) -> &str {
        match self {
            AnyMeta::Stream(m) => &m.file_name,
            AnyMeta::Zk(m) => &m.file_name,
        }
    }
}

/// Keep secrets out of core dumps, and out of reach of other processes of the
/// same user while the tool runs: on Linux by marking the process
/// non-dumpable (no ptrace, no /proc/<pid>/mem), on macOS by refusing debugger
/// attachment. macOS also exposes memory through the task port, which the
/// hardened runtime closes (see `warn_if_not_hardened`).
pub fn harden_process() {
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
pub fn warn_if_not_hardened() {
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
        let exe = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_else(|_| "this tool".into());
        eprintln!(
            "note: this build isn't signed with the hardened runtime, so a program with debugger rights could read its memory. Sign it once after each build:\n  codesign --force --options runtime --sign - \"{exe}\"\n"
        );
    }
}

#[cfg(not(target_os = "macos"))]
pub fn warn_if_not_hardened() {}

pub fn fingerprint(input: &Path) -> Result<()> {
    let data = fs::read(input).with_context(|| format!("reading {}", input.display()))?;
    out!("{}", zk::fingerprint_hex(&data));
    Ok(())
}

pub fn kib(v: u64) -> Result<u64> {
    v.checked_mul(1024).context("--max-kib is too large")
}

pub fn read_meta(p: &Path) -> Result<AnyMeta> {
    let s = fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?;
    let v: serde_json::Value = serde_json::from_str(&s).context("metadata is not valid JSON")?;
    Ok(match v.get("format").and_then(|f| f.as_str()) {
        Some(zk::FORMAT) => AnyMeta::Zk(zk::ZkMetadata::from_json(&s)?),
        _ => AnyMeta::Stream(Metadata::from_json(&s)?),
    })
}

/// `name.meta.json` -> `name.enc` / `name.proof`
pub fn sibling(meta: &Path, ext: &str) -> PathBuf {
    let s = meta.to_string_lossy();
    match s.strip_suffix(".meta.json") {
        Some(base) => PathBuf::from(format!("{base}{ext}")),
        None => with_suffix(meta, ext),
    }
}

pub fn with_suffix(p: &Path, suffix: &str) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

pub fn print_pubkey(pk: &CampaignKey) {
    let (x, y) = pk.xy_hex();
    out!("campaign key (share with creators): {}", pk.compressed_hex());
    out!("KEY_X={x}");
    out!("KEY_Y={y}");
    out!("keyAddress (contract check): {}", pk.eth_address());
}

pub fn read_secret_file(p: &Path) -> Result<CampaignSecret> {
    let s = fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?;
    Ok(CampaignSecret::from_hex(&s)?)
}

pub fn write_secret(p: &Path, hex: &str) -> Result<()> {
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
