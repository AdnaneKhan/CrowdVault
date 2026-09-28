//! The one-file layout shared by ordinary and proven sealed files:
//!
//! ```text
//!   magic (8) ‖ body ‖ footer (JSON metadata) ‖ footer length (u32, LE) ‖ FOOTER_MAGIC (8)
//! ```
//!
//! The metadata goes last so sealing stays a single pass: the file's length and
//! hash are only known once all of it has been read. Readers find the footer
//! from the end of the file, so they need to seek.

use std::io::{Read, Seek, SeekFrom};

use crate::{read_full, Error, Result};

pub const FOOTER_MAGIC: &[u8; 8] = b"CVFOOTER";
/// Metadata is a few hundred bytes; anything much larger is refused unread.
pub const MAX_FOOTER: usize = 64 * 1024;
const TRAILER: u64 = 4 + FOOTER_MAGIC.len() as u64;
const MAGIC_LEN: u64 = 8;

/// Magics of the earlier two-file formats (`.enc` beside a `.meta.json`).
const OLD_MAGICS: [&[u8; 8]; 2] = [b"CVENC2\0\0", b"CVZK1\0\0\0"];

/// A sealed file's parts, as found from its ends.
pub struct Footer {
    pub magic: [u8; 8],
    /// The metadata exactly as written.
    pub json: Vec<u8>,
    /// Bytes between the magic and the footer.
    pub body_len: u64,
}

/// `footer ‖ length ‖ FOOTER_MAGIC`, to append after the body.
pub(crate) fn trailer(footer: &[u8]) -> Result<Vec<u8>> {
    if footer.len() > MAX_FOOTER {
        return Err(Error::Malformed("metadata too large (is the file name very long?)"));
    }
    let mut t = footer.to_vec();
    t.extend_from_slice(&(footer.len() as u32).to_le_bytes());
    t.extend_from_slice(FOOTER_MAGIC);
    Ok(t)
}

/// Reads the magic and the footer. Leaves the reader at an unspecified position.
pub fn read_footer<R: Read + Seek>(r: &mut R) -> Result<Footer> {
    let total = r.seek(SeekFrom::End(0))?;
    r.seek(SeekFrom::Start(0))?;
    let mut magic = [0u8; 8];
    let n = read_full(r, &mut magic)?;
    if OLD_MAGICS.contains(&&magic) || magic.first() == Some(&b'{') {
        return Err(Error::OldFormat);
    }
    if n < 8 || !(&magic == crate::FILE_MAGIC || &magic == crate::zk::FILE_MAGIC) {
        return Err(Error::NotEncrypted);
    }
    if total < MAGIC_LEN + TRAILER {
        return Err(Error::NoFooter);
    }
    r.seek(SeekFrom::Start(total - TRAILER))?;
    let mut t = [0u8; TRAILER as usize];
    if read_full(r, &mut t)? != t.len() || &t[4..] != FOOTER_MAGIC {
        return Err(Error::NoFooter);
    }
    let len = u32::from_le_bytes(t[..4].try_into().expect("4 bytes")) as u64;
    if len > MAX_FOOTER as u64 || MAGIC_LEN + len + TRAILER > total {
        return Err(Error::Malformed("footer length"));
    }
    let body_len = total - MAGIC_LEN - len - TRAILER;
    r.seek(SeekFrom::Start(MAGIC_LEN + body_len))?;
    let mut json = vec![0u8; len as usize];
    if read_full(r, &mut json)? != json.len() {
        return Err(Error::NoFooter);
    }
    Ok(Footer { magic, json, body_len })
}

/// Positions the reader at the start of the body.
pub(crate) fn seek_body<R: Seek>(r: &mut R) -> Result<()> {
    r.seek(SeekFrom::Start(MAGIC_LEN))?;
    Ok(())
}
