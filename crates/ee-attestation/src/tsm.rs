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
}
