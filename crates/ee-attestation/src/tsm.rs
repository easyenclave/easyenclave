use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use ee_common::error::{AppError, AppResult};

const QUOTE_HEADER_SIZE: usize = 48;
const TD_REPORT_SIZE: usize = 584;
const TD_REPORT_OFFSET: usize = QUOTE_HEADER_SIZE;
const MRTD_OFFSET: usize = TD_REPORT_OFFSET + 136;
const RTMR_BASE_OFFSET: usize = TD_REPORT_OFFSET + 328;
const REPORT_DATA_OFFSET: usize = TD_REPORT_OFFSET + 520;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedQuote {
    pub version: u16,
    pub quote_size: usize,
    pub mrtd: [u8; 48],
    pub rtmrs: [[u8; 48]; 4],
    pub report_data: [u8; 64],
}

impl ParsedQuote {
    pub fn mrtd_hex(&self) -> String {
        hex(&self.mrtd)
    }

    pub fn rtmr_hex(&self) -> [String; 4] {
        [
            hex(&self.rtmrs[0]),
            hex(&self.rtmrs[1]),
            hex(&self.rtmrs[2]),
            hex(&self.rtmrs[3]),
        ]
    }

    pub fn report_data_hex(&self) -> String {
        hex(&self.report_data)
    }
}

pub fn parse_tdx_quote(quote: &[u8]) -> AppResult<ParsedQuote> {
    if quote.len() < QUOTE_HEADER_SIZE + TD_REPORT_SIZE {
        return Err(AppError::InvalidInput(format!(
            "quote too short: got {} bytes",
            quote.len()
        )));
    }

    let version = u16::from_le_bytes([quote[0], quote[1]]);

    let mrtd = copy_fixed_48(quote, MRTD_OFFSET)?;
    let rtmrs = [
        copy_fixed_48(quote, RTMR_BASE_OFFSET)?,
        copy_fixed_48(quote, RTMR_BASE_OFFSET + 48)?,
        copy_fixed_48(quote, RTMR_BASE_OFFSET + 96)?,
        copy_fixed_48(quote, RTMR_BASE_OFFSET + 144)?,
    ];
    let report_data = copy_fixed_64(quote, REPORT_DATA_OFFSET)?;

    Ok(ParsedQuote {
        version,
        quote_size: quote.len(),
        mrtd,
        rtmrs,
        report_data,
    })
}

pub fn parse_tdx_quote_base64(quote_b64: &str) -> AppResult<ParsedQuote> {
    let quote = base64::engine::general_purpose::STANDARD
        .decode(quote_b64)
        .map_err(|e| AppError::InvalidInput(format!("invalid base64 quote: {e}")))?;
    parse_tdx_quote(&quote)
}

pub fn extract_mrtd_hex(quote: &ParsedQuote) -> String {
    quote.mrtd_hex()
}

pub fn extract_rtmr_hex(quote: &ParsedQuote) -> [String; 4] {
    quote.rtmr_hex()
}

pub fn extract_report_data_hex(quote: &ParsedQuote) -> String {
    quote.report_data_hex()
}

pub fn report_data_starts_with_nonce_hex(quote: &ParsedQuote, nonce_hex: &str) -> bool {
    let expected = nonce_hex.trim().to_ascii_lowercase();
    if expected.is_empty()
        || !expected.len().is_multiple_of(2)
        || !expected.chars().all(|c| c.is_ascii_hexdigit())
    {
        return false;
    }
    quote.report_data_hex().starts_with(&expected)
}

pub fn generate_tdx_quote(
    report_root: impl AsRef<Path>,
    user_data: Option<&[u8]>,
) -> AppResult<Vec<u8>> {
    let report_root = report_root.as_ref();
    if !report_root.exists() {
        return Err(AppError::External(format!(
            "TSM report path does not exist: {}",
            report_root.display()
        )));
    }

    let report_id = format!(
        "quote_{}_{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AppError::Internal)?
            .as_nanos()
    );
    let report_dir = report_root.join(report_id);

    if report_dir.exists() {
        fs::remove_dir(&report_dir)
            .map_err(|e| AppError::External(format!("failed to remove stale report dir: {e}")))?;
    }

    fs::create_dir(&report_dir)
        .map_err(|e| AppError::External(format!("failed to create report dir: {e}")))?;

    let inblob = report_dir.join("inblob");
    let outblob = report_dir.join("outblob");

    let result = (|| {
        let mut payload = [0_u8; 64];
        if let Some(user_data) = user_data {
            let copy_len = user_data.len().min(payload.len());
            payload[..copy_len].copy_from_slice(&user_data[..copy_len]);
        }

        fs::write(&inblob, payload)
            .map_err(|e| AppError::External(format!("failed writing inblob: {e}")))?;
        fs::read(&outblob).map_err(|e| AppError::External(format!("failed reading outblob: {e}")))
    })();

    let _ = fs::remove_dir(&report_dir);
    result
}

pub fn generate_tdx_quote_base64(
    report_root: impl AsRef<Path>,
    user_data: Option<&[u8]>,
) -> AppResult<String> {
    let quote = generate_tdx_quote(report_root, user_data)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(quote))
}

fn copy_fixed_48(quote: &[u8], offset: usize) -> AppResult<[u8; 48]> {
    let slice = quote.get(offset..offset + 48).ok_or_else(|| {
        AppError::InvalidInput("quote missing expected 48-byte field".to_string())
    })?;
    let mut out = [0_u8; 48];
    out.copy_from_slice(slice);
    Ok(out)
}

fn copy_fixed_64(quote: &[u8], offset: usize) -> AppResult<[u8; 64]> {
    let slice = quote.get(offset..offset + 64).ok_or_else(|| {
        AppError::InvalidInput("quote missing expected 64-byte field".to_string())
    })?;
    let mut out = [0_u8; 64];
    out.copy_from_slice(slice);
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{:02x}", b);
    }
    out
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;

    use super::{
        extract_mrtd_hex, extract_report_data_hex, extract_rtmr_hex, parse_tdx_quote,
        parse_tdx_quote_base64, report_data_starts_with_nonce_hex,
    };

    fn fake_quote(mrtd: [u8; 48], rtmrs: [[u8; 48]; 4], report_data: [u8; 64]) -> Vec<u8> {
        let mut quote = vec![0_u8; 48 + 584];
        quote[0..2].copy_from_slice(&4_u16.to_le_bytes());

        let td_report = 48;
        quote[td_report + 136..td_report + 184].copy_from_slice(&mrtd);
        quote[td_report + 328..td_report + 376].copy_from_slice(&rtmrs[0]);
        quote[td_report + 376..td_report + 424].copy_from_slice(&rtmrs[1]);
        quote[td_report + 424..td_report + 472].copy_from_slice(&rtmrs[2]);
        quote[td_report + 472..td_report + 520].copy_from_slice(&rtmrs[3]);
        quote[td_report + 520..td_report + 584].copy_from_slice(&report_data);

        quote
    }

    #[test]
    fn parse_extracts_measurements_at_expected_offsets() {
        let mrtd = [0xaa; 48];
        let rtmrs = [[0xbb; 48], [0xcc; 48], [0xdd; 48], [0xee; 48]];
        let report_data = [0x11; 64];
        let quote = fake_quote(mrtd, rtmrs, report_data);

        let parsed = parse_tdx_quote(&quote).expect("parse");
        assert_eq!(parsed.version, 4);
        assert_eq!(extract_mrtd_hex(&parsed), "aa".repeat(48));

        let rtmr_hex = extract_rtmr_hex(&parsed);
        assert_eq!(rtmr_hex[0], "bb".repeat(48));
        assert_eq!(rtmr_hex[1], "cc".repeat(48));
        assert_eq!(rtmr_hex[2], "dd".repeat(48));
        assert_eq!(rtmr_hex[3], "ee".repeat(48));
        assert_eq!(extract_report_data_hex(&parsed), "11".repeat(64));
    }

    #[test]
    fn parse_base64_quote() {
        let quote = fake_quote(
            [0x22; 48],
            [[0x33; 48], [0x44; 48], [0x55; 48], [0x66; 48]],
            [0x77; 64],
        );
        let quote_b64 = base64::engine::general_purpose::STANDARD.encode(quote);
        let parsed = parse_tdx_quote_base64(&quote_b64).expect("parse");
        assert_eq!(parsed.mrtd_hex(), "22".repeat(48));
        assert_eq!(parsed.report_data_hex(), "77".repeat(64));
    }

    #[test]
    fn parse_rejects_short_quote() {
        let quote = vec![0_u8; 64];
        let err = parse_tdx_quote(&quote).expect_err("must fail");
        assert!(err.to_string().contains("quote too short"));
    }

    #[test]
    fn report_data_nonce_prefix_check() {
        let mut report_data = [0_u8; 64];
        report_data[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let quote = fake_quote(
            [0x00; 48],
            [[0x00; 48], [0x00; 48], [0x00; 48], [0x00; 48]],
            report_data,
        );
        let parsed = parse_tdx_quote(&quote).expect("parse");

        assert!(report_data_starts_with_nonce_hex(&parsed, "deadbeef"));
        assert!(!report_data_starts_with_nonce_hex(&parsed, "deadbee0"));
        assert!(!report_data_starts_with_nonce_hex(&parsed, "not-hex"));
    }
}
