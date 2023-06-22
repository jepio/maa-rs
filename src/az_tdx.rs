use anyhow::*;
use base64::Engine as _;
use ioctl_sys::ioctl;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Error;
use std::os::unix::io::AsRawFd;

// Length of the REPORTDATA used in TDG.MR.REPORT TDCALL
const TDX_REPORTDATA_LEN: usize = 64;

// Length of TDREPORT used in TDG.MR.REPORT TDCALL
const TDX_REPORT_LEN: usize = 1024;

#[repr(C)]
#[derive(Debug)]
pub struct TdxReportReq {
    reportdata: [u8; TDX_REPORTDATA_LEN],
    tdreport: [u8; TDX_REPORT_LEN],
}

impl TdxReportReq {
    pub fn new(reportdata: [u8; TDX_REPORTDATA_LEN]) -> Self {
        Self {
            reportdata,
            tdreport: [0; TDX_REPORT_LEN],
        }
    }
}

#[derive(Serialize, Deserialize)]
struct AzTdQuoteRequest {
    report: String,
}
#[derive(Serialize, Deserialize, Debug)]
struct AzTdQuoteResponse {
    quote: String,
}

impl Default for TdxReportReq {
    fn default() -> Self {
        Self {
            reportdata: [0; TDX_REPORTDATA_LEN],
            tdreport: [0; TDX_REPORT_LEN],
        }
    }
}

ioctl!(readwrite tdx_cmd_get_report0 with b'T', 0x01; TdxReportReq);

const IMDS_TDQUOTE_ENDPOINT : &str = "http://169.254.169.254/acc/tdquote";

fn get_tdx_evidence(report_data: [u8; 64]) -> Result<Vec<u8>> {
    let file = OpenOptions::new().write(true).open("/dev/tdx_guest").context("error opening tdx_guest device")?;
    let fd = file.as_raw_fd();
    let mut tdx_req = TdxReportReq::new(report_data);
    unsafe {
        let err = tdx_cmd_get_report0(fd, &mut tdx_req);
        if err != 0 {
            return Err(anyhow!(
                "TDX Attester: ioctl failed: {}",
                Error::last_os_error()
            ));
        }
    }
    let report = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(tdx_req.tdreport);
    let tdquotereq = AzTdQuoteRequest { report };
    let req = reqwest::blocking::Client::new()
        .post(IMDS_TDQUOTE_ENDPOINT)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(reqwest::header::ACCEPT, "application/json")
        .body(serde_json::to_string(&tdquotereq)?)
        .send()?;
    let tdquoteresp = req.json::<AzTdQuoteResponse>()?;
    let quote = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(tdquoteresp.quote)?;
    Ok(quote)
}

pub(crate) fn make_quote(runtimedata: &super::maa::MAARuntimeData) -> Result<Vec<u8>> {
    let arr = crate::maa::runtime_data_to_sha256(runtimedata);
    get_tdx_evidence(arr)
}