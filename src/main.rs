use reqwest::blocking::Response;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use serde_with::base64::{Base64, UrlSafe};
use serde_with::formats::{Unpadded};
use base64::{engine, Engine};

const MAA_URL: &str = "https://maajepio.eus.attest.azure.net";

#[derive(Deserialize, Debug)]
struct MaaCert {
    kid : String,
    kty : String,
    x5c : Vec<String>,
}

#[derive(Deserialize, Debug)]
struct MAACerts {
    keys : Vec<MaaCert>,
}

fn fetch_certs() -> Result<MAACerts, Box<dyn std::error::Error>> {
    let resp = reqwest::blocking::get(MAA_URL.to_string() + "/certs")?;
    let maacerts : MAACerts = resp.json()?;
    Ok(maacerts)
}

#[serde_as]
#[derive(Serialize, Debug)]
struct MAASnpReport {
    SnpReport : String,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    VcekCertChain : String,
}

#[derive(Serialize, Debug)]
enum MAARuntimeDataType {
    JSON,
    Binary,
}

#[serde_as]
#[derive(Serialize, Debug)]
struct MAARuntimeData {
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    data: String,
    dataType: MAARuntimeDataType,
}

#[serde_as]
#[derive(Serialize, Debug)]
struct MAASnpAttestRequest {
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    report: String,
    runtimeData: MAARuntimeData,
    nonce: String,
}

fn create_maa_test_request() -> String {
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
    serde_json::to_string(&request).unwrap()
}

const TEST_REQUEST : &str = include_str!("../test/request.json");

fn attest_snp() -> Result<Response, Box<dyn std::error::Error>> {
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(MAA_URL.to_string() + "/attest/SevSnpVm?api-version=2022-08-01")
        .header("Content-Type", "application/json")
        .body(create_maa_test_request())
        .send()?;
    Ok(resp)
}

fn main() -> Result<(), Box<dyn std::error::Error>>{
//    let certs = fetch_certs()?;
//    println!("certs: {:?}", certs);
    let resp = attest_snp()?;
    println!("resp: {:?}", resp.status());
    println!("resp: {}", resp.text()?);
    Ok(())
}
