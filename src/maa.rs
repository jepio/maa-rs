use anyhow::anyhow;
use jsonwebtoken::jwk::Jwk;
use reqwest;
use std::io::prelude;
use jsonwebtoken::jwk::JwkSet;
use serde::{Deserialize, Serialize};
use base64::{Engine as _};
use base64;

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

// Microsoft Azure Attestation wrapper
pub struct MAA {
    certs: JwkSet,
    url: String,
}

impl MAA {
    pub fn new(url: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let certs = fetch_cert_set(url)?;
        Ok(Self{ certs, url: url.to_string()})
    }

    pub fn find(&self, kid: &str) -> Option<&Jwk> {
        self.certs.find(kid)
    }
}

fn fetch_cert_set(url: &str) -> Result<JwkSet, Box<dyn std::error::Error>> {
    let resp = reqwest::blocking::get(url.to_string() + "/certs")?;
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
