// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use anyhow::{anyhow, Context};
use openssl::x509::X509;
use sev::firmware::guest::types::AttestationReport;
use thiserror::Error;
use std::io::prelude::*;

const KDS_CERT_SITE: &str = "https://kdsintf.amd.com";
const KDS_VCEK: &str = "/vcek/v1";
const SEV_PROD_NAME: &str = "Milan";
const KDS_CERT_CHAIN: &str = "cert_chain";

pub struct AmdChain {
    pub ask: X509,
    pub ark: X509,
}
pub struct Vcek(pub X509);

#[derive(Error, Debug)]
pub enum HttpError {
    #[error("HTTP error")]
    Http(#[from] Box<ureq::Error>),
    #[error("failed to read HTTP response")]
    Io(#[from] std::io::Error),
}

fn get(url: &str) -> Result<Vec<u8>, HttpError> {
    let mut body = ureq::get(url).call().map_err(Box::new)?.into_reader();
    let mut buffer = Vec::new();
    body.read_to_end(&mut buffer)?;
    Ok(buffer)
}

#[derive(Error, Debug)]
pub enum AmdKdsError {
    #[error("openssl error")]
    OpenSsl(#[from] openssl::error::ErrorStack),
    #[error("Http error")]
    Http(#[from] HttpError),
}

/// Retrieve the AMD chain of trust (ASK & ARK) from AMD's KDS
fn get_cert_chain() -> Result<AmdChain, AmdKdsError> {
    let url = format!("{KDS_CERT_SITE}{KDS_VCEK}/{SEV_PROD_NAME}/{KDS_CERT_CHAIN}");
    let bytes = get(&url)?;

    let certs = X509::stack_from_pem(&bytes)?;
    let ask = certs[0].clone();
    let ark = certs[1].clone();

    let chain = AmdChain { ask, ark };

    Ok(chain)
}

fn hexify(bytes: &[u8]) -> String {
    let mut hex_string = String::new();
    for byte in bytes {
        hex_string.push_str(&format!("{:02x}", byte));
    }
    hex_string
}

/// Retrieve a VCEK cert from AMD's KDS, based on an AttestationReport's platform information
fn get_vcek(report: &AttestationReport) -> Result<Vcek, AmdKdsError> {
    let hw_id = hexify(&report.chip_id);
    let url = format!(
        "{KDS_CERT_SITE}{KDS_VCEK}/{SEV_PROD_NAME}/{hw_id}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
        report.reported_tcb.boot_loader,
        report.reported_tcb.tee,
        report.reported_tcb.snp,
        report.reported_tcb.microcode
    );

    let bytes = get(&url)?;
    let cert = X509::from_der(&bytes)?;
    let vcek = Vcek(cert);
    Ok(vcek)
}

pub fn fetch_vcek_chain(snp_report: &AttestationReport) -> Result<String, Box<dyn std::error::Error>> {
    let certchain = {
        let certchain = get_cert_chain()?;
        let vcek = get_vcek(&snp_report)?;
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

pub fn fetch_cached_vcek_chain(snp_report: &AttestationReport) -> Result<String, Box<dyn std::error::Error>> {
    let certchain = std::fs::read_to_string(sev::cached_chain::home().unwrap());
    let certchain = certchain.or_else(|_| {
        let path = sev::cached_chain::home().unwrap();
        match fetch_vcek_chain(&snp_report) {
            Ok(certchain) => {
                let mut file = std::fs::File::create(path.clone()).context(format!("create {}", path.display()))?;
                file.write_all(certchain.as_bytes())?;
                Ok(certchain)
            },
            Err(e) => Err(anyhow!(format!("failed to write {}: {:?}; mkdir the directory manually", path.display(), e))),
        }
    })?;
    Ok(certchain)
}