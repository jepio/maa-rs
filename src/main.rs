#![allow(dead_code)]

use anyhow::{Context, anyhow};
use jsonwebtoken::{decode, Validation, Algorithm, DecodingKey};
use jsonwebtoken::jwk::{JwkSet, Jwk};
use std::collections::HashMap;
use std::io::prelude::*;
use reqwest::blocking::Response;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use serde_with::base64::{Base64, UrlSafe};
use serde_with::formats::{Unpadded};
use sev::firmware::host::types::Indeterminate::{Known, Unknown};
use sev::firmware::guest::types::AttestationReport;
use base64::{Engine as _};
use base64;
use sha2::{Sha256, Digest};

mod amd_kds;

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

// MAA provides a JWK which is missing some fields for interoperability
#[derive(Deserialize, Debug, Serialize)]
struct MAAJwk {
    kid : String,
    kty : String,
    e : String,
    n : String,
    x5c: Vec<String>,
    #[serde(rename(serialize = "use"))]
    keyuse : String,
    alg : String,
}

fn fetch_cert_set() -> Result<JwkSet, Box<dyn std::error::Error>> {
    let resp = reqwest::blocking::get(MAA_URL.to_string() + "/certs")?;
    let certs : MAACerts = resp.json()?;
    let mut jwkset = Vec::<Jwk>::default();
    for cert in certs.keys.iter() {
        let cert_b64 = cert.x5c[0].as_bytes();
        let cert_der = base64::engine::general_purpose::STANDARD.decode(cert_b64).unwrap();
        let x509 = openssl::x509::X509::from_der(&cert_der[..])?;
        let pubkey = x509.public_key()?;
        let kty = cert.kty.as_str();
        match kty {
            "RSA" => {
                let rsapubkey = pubkey.rsa()?;
                let e = rsapubkey.e().to_vec();
                let n = rsapubkey.n().to_vec();
                let maajwk = MAAJwk{
                    kid: cert.kid.clone(),
                    kty: cert.kty.clone(),
                    e: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(e),
                    n: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(n),
                    x5c: cert.x5c.clone(),
                    keyuse: "sig".to_string(),
                    alg: "RS256".to_string(),
                };
                // convert MAAJwk to Jwk through json intermediate
                // representation to make sure we're doing this right
                let jwkstr = serde_json::to_string(&maajwk)?;
                let jwk : Jwk = serde_json::from_str(&jwkstr)?;
                jwkset.push(jwk);
            },
            _ => {
                return Err(Box::from(anyhow!("Unsupported key type: {}", kty)));
            }
        }
    }
    Ok(JwkSet{ keys: jwkset })
}

#[allow(non_snake_case)]
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

#[allow(non_snake_case)]
#[serde_as]
#[derive(Serialize, Debug)]
struct MAARuntimeData {
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    data: String,
    dataType: MAARuntimeDataType,
}

#[allow(non_snake_case)]
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

fn amd_kds_fetch_chain(snp_report: &AttestationReport) -> Result<String, Box<dyn std::error::Error>> {
    let certchain = {
        let certchain = amd_kds::get_cert_chain()?;
        let vcek: amd_kds::Vcek = amd_kds::get_vcek(&snp_report)?;
        // convert X509 to PEM string
        let mut certchain_str = String::new();
        for cert in [vcek.0, certchain.ask, certchain.ark] {
            let v = cert.to_pem()?;
            certchain_str.push_str(String::from_utf8(v)?.as_str());
        }
        certchain_str
    };
    Ok(certchain)
}

fn attest_snp(reportdata: &str) -> Result<Response, Box<dyn std::error::Error>> {
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
    let certchain = std::fs::read_to_string(sev::cached_chain::home().unwrap()).or_else(|_| {
        let path = sev::cached_chain::home().unwrap();
        match amd_kds_fetch_chain(&snp_report) {
            Ok(certchain) => {
                let mut file = std::fs::File::create(path.clone()).context(format!("create {}", path.display()))?;
                file.write_all(certchain.as_bytes())?;
                Ok(certchain)
            },
            Err(e) => Err(anyhow!(format!("failed to write {}: {:?}", path.display(), e))),
        }
    })?;
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
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(MAA_URL.to_string() + "/attest/SevSnpVm?api-version=2022-08-01")
        .header("Content-Type", "application/json")
        .json(&maa_req)
        .send()?;
    Ok(resp)
}

fn main() -> Result<(), Box<dyn std::error::Error>>{
    let certset= fetch_cert_set()?;
    let resp = attest_snp("{\"runtimedata\": 1}")?;
    println!("resp: {:?}", resp.status());
    let body = resp.json::<HashMap<String, String>>()?;
    println!("resp: {}", serde_json::to_value(&body)?);
    let token = body.get("token").unwrap();
    let header = jsonwebtoken::decode_header(&token)?;
    println!("token: {}", serde_json::to_value(&header)?);
    let kid = header.kid.unwrap();
    let cert = certset.find(&kid).unwrap();
    let alg = cert.common.algorithm.ok_or(anyhow!("Get jwk alg failed"))?;
    let dkey = DecodingKey::from_jwk(cert)?;
    let token = decode::<serde_json::Value>(token, &dkey, &Validation::new(alg))?;
    println!("token: {}", serde_json::to_string(&token.claims)?);
    Ok(())
}
