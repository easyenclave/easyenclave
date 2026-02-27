use ee_common::error::{AppError, AppResult};

#[derive(Debug, Clone)]
pub struct ParsedQuote {
    pub mrtd_hex: String,
    pub nonce_hex: String,
}

pub fn parse_quote_blob(quote: &[u8]) -> AppResult<ParsedQuote> {
    if quote.len() < 64 {
        return Err(AppError::BadRequest("quote blob too small".to_owned()));
    }

    let mrtd_hex = hex_encode(&quote[0..48]);
    let nonce_hex = hex_encode(&quote[48..64]);

    Ok(ParsedQuote {
        mrtd_hex,
        nonce_hex,
    })
}

pub fn build_mock_quote_blob(mrtd_hex: &str, nonce_hex: &str) -> AppResult<Vec<u8>> {
    let mrtd = hex_decode(mrtd_hex)?;
    if mrtd.len() != 48 {
        return Err(AppError::BadRequest(
            "mock quote mrtd must decode to 48 bytes".to_owned(),
        ));
    }

    let nonce = hex_decode(nonce_hex)?;
    if nonce.len() != 16 {
        return Err(AppError::BadRequest(
            "mock quote nonce must decode to 16 bytes".to_owned(),
        ));
    }

    let mut blob = vec![0u8; 64];
    blob[0..48].copy_from_slice(&mrtd);
    blob[48..64].copy_from_slice(&nonce);
    Ok(blob)
}

pub fn report_data_from_nonce(nonce_hex: &str) -> AppResult<[u8; 64]> {
    if nonce_hex.is_empty() {
        return Err(AppError::BadRequest("nonce is required".to_owned()));
    }

    let mut report_data = [0u8; 64];
    let bytes = nonce_hex.as_bytes();
    let copy_len = bytes.len().min(64);
    report_data[..copy_len].copy_from_slice(&bytes[..copy_len]);
    Ok(report_data)
}

fn hex_encode(input: &[u8]) -> String {
    input.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(input: &str) -> AppResult<Vec<u8>> {
    let value = input.trim();
    if !value.len().is_multiple_of(2) {
        return Err(AppError::BadRequest("hex string has odd length".to_owned()));
    }

    (0..value.len())
        .step_by(2)
        .map(|idx| {
            u8::from_str_radix(&value[idx..idx + 2], 16)
                .map_err(|_| AppError::BadRequest("invalid hex string".to_owned()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_quote_blob_extracts_fields() {
        let mut blob = vec![0u8; 64];
        blob[0] = 0xaa;
        blob[48] = 0xbb;
        let parsed = parse_quote_blob(&blob).expect("must parse");
        assert!(parsed.mrtd_hex.starts_with("aa"));
        assert!(parsed.nonce_hex.starts_with("bb"));
    }

    #[test]
    fn build_and_parse_mock_quote_roundtrip() {
        let mrtd = "ab".repeat(48);
        let nonce = "cd".repeat(16);
        let blob = build_mock_quote_blob(&mrtd, &nonce).expect("must build");
        let parsed = parse_quote_blob(&blob).expect("must parse");
        assert_eq!(parsed.mrtd_hex, mrtd);
        assert_eq!(parsed.nonce_hex, nonce);
    }
}
