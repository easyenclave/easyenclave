use ee_attestation::tsm::{generate_tdx_quote_base64, parse_tdx_quote_base64};
use ee_common::error::AppResult;
use serde_json::json;

const TSM_REPORT_PATH: &str = "/sys/kernel/config/tsm/report";

pub fn run_measure_mode() -> AppResult<()> {
    let quote_b64 = generate_tdx_quote_base64(TSM_REPORT_PATH, None)?;
    let parsed = parse_tdx_quote_base64(&quote_b64)?;
    let rtmrs = parsed.rtmr_hex();

    let payload = json!({
        "mrtd": parsed.mrtd_hex(),
        "rtmr0": rtmrs[0],
        "rtmr1": rtmrs[1],
        "rtmr2": rtmrs[2],
        "rtmr3": rtmrs[3],
    });

    println!("EASYENCLAVE_MEASUREMENTS={payload}");
    Ok(())
}
