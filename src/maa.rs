use anyhow::anyhow;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{DecodingKey, TokenData, Validation};

use serde::de::DeserializeOwned;
use serde_with::base64::{Base64, UrlSafe};
use serde_with::formats::Unpadded;
use serde_with::serde_as;
use std::collections::HashMap;


use base64::Engine as _;
use jsonwebtoken::jwk::JwkSet;
use serde::{Deserialize, Serialize};
use sev::firmware::guest::types::AttestationReport;
use sev::firmware::host::types::Indeterminate::{Known, Unknown};
use sha2::{Digest, Sha256};

#[allow(non_snake_case)]
#[serde_as]
#[derive(Serialize, Debug)]
pub struct MAASnpReport {
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    pub SnpReport: Vec<u8>,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    pub VcekCertChain: String,
}

#[allow(non_snake_case)]
#[serde_as]
#[derive(Serialize, Debug)]
#[serde(tag = "dataType")]
pub enum MAARuntimeData {
    JSON {
        #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
        data: String,
    },
    Binary {
        #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
        data: Vec<u8>,
    },
}

#[allow(non_snake_case)]
#[serde_as]
#[derive(Serialize, Debug)]
pub struct MAASnpAttestRequest {
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    pub report: String,
    pub runtimeData: MAARuntimeData,
    pub nonce: String,
}

// MAA provides a JWK which is missing some fields for interoperability
#[derive(Deserialize, Debug, Serialize)]
struct MAAJwk {
    kid: String,
    kty: String,
    e: Option<String>,
    n: Option<String>,
    x5c: Vec<String>,
    #[serde(rename(serialize = "use"))]
    keyuse: Option<String>,
    alg: Option<String>,
}

#[derive(Deserialize, Debug)]
struct MAACerts {
    keys: Vec<MAAJwk>,
}

// Microsoft Azure Attestation wrapper
pub struct MAA {
    certs: Option<JwkSet>,
    url: String,
}

impl MAA {
    // a verifier can both attest (fetch the token) and verify (check the token)
    pub fn new_verifier(url: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let certs = fetch_cert_set(url)?;
        Ok(Self {
            certs: Some(certs),
            url: url.to_string(),
        })
    }

    // can be used to fetch an MAA token as attestation evidence
    pub fn new_attester(url: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            certs: None,
            url: url.to_string(),
        })
    }

    pub fn find(&self, kid: &str) -> Option<&Jwk> {
        self.certs.as_ref().and_then(|certs| certs.find(kid))
    }

    pub fn attest_sev_snp_vm(
        &self,
        maasnpreq: MAASnpAttestRequest,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let body = serde_json::to_string(&maasnpreq)?;
        let token = self.raw_request("/attest/SevSnpVm?api-version=2022-08-01", &body)?;
        Ok(token)
    }

    pub fn raw_request(
        &self,
        path: &str,
        body: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let client = reqwest::blocking::Client::new();
        let resp = client
            .post(self.url.to_string() + path)
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()?;
        if !resp.status().is_success() {
            return Err(Box::from(anyhow!("HTTP error {:?}", resp)));
        }
        let resp = resp.json::<HashMap<String, String>>()?;
        let token = resp.get("token").ok_or(anyhow!("token not found"))?;
        Ok(token.to_string())
    }

    pub fn verify<Claims: DeserializeOwned>(
        &self,
        token: &str,
    ) -> Result<TokenData<Claims>, Box<dyn std::error::Error>> {
        let header = jsonwebtoken::decode_header(token)?;
        let kid = header.kid.ok_or(anyhow!("kid not found"))?;
        let cert = self.find(&kid).ok_or(anyhow!("cert not found"))?;
        let alg = cert.common.algorithm.ok_or(anyhow!("Get jwk alg failed"))?;
        let dkey = DecodingKey::from_jwk(cert)?;
        let token_data = jsonwebtoken::decode::<Claims>(token, &dkey, &Validation::new(alg))?;
        Ok(token_data)
    }
}

pub fn gather_snp_evidence(reportdata: &[u8]) -> Result<MAASnpReport, Box<dyn std::error::Error>> {
    let mut hasher = Sha256::new();
    hasher.update(reportdata);
    let hash = hasher.finalize();
    let mut arr: [u8; 64] = [0; 64];
    // set the first 32 bytes to the hash
    arr[..32].copy_from_slice(&hash[..]);

    let mut firmware = sev::firmware::guest::Firmware::open()?;
    let snp_report_req = sev::firmware::guest::types::SnpReportReq::new(Some(arr), 0);
    let snp_report_res = firmware.snp_get_report(None, snp_report_req);
    let snp_report_res: Result<AttestationReport, Box<dyn std::error::Error>> = snp_report_res
        .map_err(|e| match e {
            Known(err) => Box::from(err),
            Unknown => Box::from("Unknown error"),
        });
    let snp_report = snp_report_res?;
    let certchain = crate::amd_kds::fetch_cached_vcek_chain(&snp_report)?;
    let snp_report_str = bincode::serialize(&snp_report)?;
    let maasnpreport = MAASnpReport {
        SnpReport: snp_report_str,
        VcekCertChain: certchain,
    };
    Ok(maasnpreport)
}

fn fetch_jwks_uri(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    let url = url.to_string() + "/.well-known/openid-configuration";
    let resp = reqwest::blocking::get(url)?;
    if !resp.status().is_success() {
        return Err(Box::from(anyhow!("HTTP error {:?}", resp)));
    }
    let config = resp.json::<serde_json::Value>()?;
    let jwks_uri = config["jwks_uri"]
        .as_str()
        .ok_or(anyhow!("jwks_uri not found"))?;
    Ok(jwks_uri.to_string())
}

fn fetch_cert_set(url: &str) -> Result<JwkSet, Box<dyn std::error::Error>> {
    let jwks_uri = fetch_jwks_uri(url)?;
    let resp = reqwest::blocking::get(jwks_uri)?;
    if !resp.status().is_success() {
        return Err(Box::from(anyhow!("HTTP error {:?}", resp)));
    }
    let certs: MAACerts = resp.json()?;
    let mut jwkset = Vec::<Jwk>::default();
    for mut cert in certs.keys.into_iter() {
        let cert_b64 = cert.x5c[0].as_bytes();
        let cert_der = base64::engine::general_purpose::STANDARD
            .decode(cert_b64)
            .unwrap();
        let x509 = openssl::x509::X509::from_der(&cert_der[..])?;
        let pubkey = x509.public_key()?;
        let kty = cert.kty.as_str();
        match kty {
            "RSA" => {
                let rsapubkey = pubkey.rsa()?;
                let e = rsapubkey.e().to_vec();
                let n = rsapubkey.n().to_vec();
                cert.e = Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(e));
                cert.n = Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(n));
                cert.keyuse = Some("sig".to_string());
                cert.alg = Some("RS256".to_string());
                // convert MAAJwk to Jwk through json intermediate
                // representation to make sure we're doing this right
                let jwkstr = serde_json::to_string(&cert)?;
                let jwk: Jwk = serde_json::from_str(&jwkstr)?;
                jwkset.push(jwk);
            }
            _ => {
                return Err(Box::from(anyhow!("Unsupported key type: {}", kty)));
            }
        }
    }
    Ok(JwkSet { keys: jwkset })
}
