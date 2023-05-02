#![allow(dead_code)]

use anyhow::{Context, anyhow};
use jsonwebtoken::{decode, Validation, Algorithm, DecodingKey};
use std::collections::HashMap;

use reqwest::blocking::Response;
use serde::{Deserialize, Serialize};

use sev::firmware::host::types::Indeterminate::{Known, Unknown};
use sev::firmware::guest::types::AttestationReport;
use base64::{Engine as _};
use base64;
use sha2::{Sha256, Digest};

mod amd_kds;

const MAA_URL: &str = "https://maajepio.eus.attest.azure.net";

mod maa;

use maa::*;

fn attest_snp(maa : &MAA, reportdata: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut hasher = Sha256::new();
    hasher.update(reportdata.as_bytes());
    let hash = hasher.finalize();
    let mut arr : [u8; 64] = [0; 64];
    // set the first 32 bytes to the hash
    arr[..32].copy_from_slice(&hash[..]);
    println!("arr: {:?}", arr);
    let mut firmware = sev::firmware::guest::Firmware::open()?;
    let snp_report_req = sev::firmware::guest::types::SnpReportReq::new(Some(arr), 0);
    let snp_report_res= firmware.snp_get_report(None, snp_report_req);
    let snp_report_res: Result<AttestationReport, Box<dyn std::error::Error>> = snp_report_res.map_err(|e|
        match e {
            Known(err) => Box::from(err),
            Unknown => Box::from("Unknown error"),
        }
    );
    let snp_report = snp_report_res?;
    let certchain = amd_kds::fetch_cached_vcek_chain(&snp_report)?;
    let snp_report_str = bincode::serialize(&snp_report)?;
    let maasnpreport = MAASnpReport{
        SnpReport: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&snp_report_str),
        VcekCertChain: certchain,
    };
    let maa_req = MAASnpAttestRequest{
        report: serde_json::to_string(&maasnpreport).unwrap(),
        runtimeData: MAARuntimeData{
            data: reportdata.to_string(),
            dataType: MAARuntimeDataType::JSON,
        },
        nonce: "nonce".to_string(),
    };
    maa.attest_sev_snp_vm(maa_req)
}

fn main() -> Result<(), Box<dyn std::error::Error>>{
    let maa = maa::MAA::new_verifier(MAA_URL)?;
    let token = attest_snp(&maa, "{\"runtimedata\": 1}")?;
    let header = jsonwebtoken::decode_header(&token)?;
    println!("token: {}", serde_json::to_value(&header)?);
    let token_data = maa.verify::<serde_json::Value>(&token)?;
    println!("token_data: {}", serde_json::to_string(&token_data.claims)?);
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    const TEST_REQUEST : &str = include_str!("../test/request.json");

    fn create_maa_test_request() -> MAASnpAttestRequest {
        let report = MAASnpReport{
                SnpReport: include_str!("../test/SnpReport").to_string(),
                VcekCertChain: include_str!("../test/VcekCertChain").to_string(),
        };
        let report_json = serde_json::to_string(&report).unwrap();
        let request = MAASnpAttestRequest{
            report: report_json,
            runtimeData: MAARuntimeData{
                data: include_str!("../test/runtimeData_data").to_string(),
                dataType: MAARuntimeDataType::JSON,
            },
            nonce: "nonce".to_string(),
        };
        request
    }
    const SHARED_MAA_URL: &str = "https://sharedeus2.eus2.attest.azure.net";

    #[test]
    fn test_attest_and_verify() -> Result<(), Box<dyn std::error::Error>> {
        let maa = maa::MAA::new_verifier(SHARED_MAA_URL)?;
        let req = create_maa_test_request();
        let token = maa.attest_sev_snp_vm(req)?;
        println!("token: {}", token);
        let token_data = maa.verify::<serde_json::Value>(&token)?;
        println!("token_data: {}", serde_json::to_string_pretty(&token_data.claims)?);
        Ok(())
    }

}