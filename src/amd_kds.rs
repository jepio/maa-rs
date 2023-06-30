// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use anyhow::{anyhow, Context, Error};
use openssl::x509::X509;
use sev::firmware::guest::AttestationReport;
use sev::firmware::host::{CertTableEntry, CertType};
use std::io::prelude::*;
use thiserror::Error;

const KDS_CERT_SITE: &str = "https://kdsintf.amd.com";
const KDS_VCEK: &str = "/vcek/v1";
const KDS_VLEK: &str = "/vlek/v1";
const SEV_PROD_NAME: &str = "Milan";
const KDS_CERT_CHAIN: &str = "cert_chain";

pub struct AmdChain {
    pub ask: X509,
    pub ark: X509,
}

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

enum AmdCertType {
    VCEK(X509),
    VLEK(X509),
}
const CERT_TYPE_VLEK : CertType = CertType::OTHER(uuid::uuid!("a8074bc2-a25a-483e-aae6-39c045a0b8a1"));

/// Retrieve the AMD chain of trust (ASK & ARK) from AMD's KDS
fn get_cert_chain(chain: &AmdCertType) -> Result<AmdChain, Error> {
    use AmdCertType::*;
    let kds_site = match chain {
        VCEK(_) => KDS_VCEK,
        VLEK(_) => KDS_VLEK,
    };
    let url = format!("{KDS_CERT_SITE}{kds_site}/{SEV_PROD_NAME}/{KDS_CERT_CHAIN}");
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
fn get_vcek(report: &AttestationReport) -> Result<AmdCertType, Error> {
    let hw_id = hexify(&report.chip_id);
    let url = format!(
        "{KDS_CERT_SITE}{KDS_VCEK}/{SEV_PROD_NAME}/{hw_id}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
        report.reported_tcb.bootloader,
        report.reported_tcb.tee,
        report.reported_tcb.snp,
        report.reported_tcb.microcode
    );

    let bytes = get(&url)?;
    let cert = X509::from_der(&bytes)
        .context("failed to parse vcek")?;
    let vcek = AmdCertType::VCEK(cert);
    Ok(vcek)
}

fn find_cert(certs : &Vec<CertTableEntry>, cert_type: CertType) -> Option<AmdCertType> {
    let elem = certs.iter().find(|&e| e.cert_type == cert_type);
    if let Some(elem) = elem {
        match cert_type {
            CertType::VCEK => X509::from_der(&elem.data[..]).map(AmdCertType::VCEK).ok(),
            CERT_TYPE_VLEK => X509::from_der(&elem.data[..]).map(AmdCertType::VLEK).ok(),
            _ => None,
        }
    } else {
        None
    }
}

pub fn fetch_vcek_chain(
    snp_report: &AttestationReport,
    certs: Option<&Vec<CertTableEntry>>,
) -> Result<String, Error> {
    let (vcek, vlek) = if let Some(certs) = certs {
        (
            find_cert(certs, CertType::VCEK),
            find_cert(certs, CERT_TYPE_VLEK),
        )
    } else {
        (None, None)
    };
    let cert = if let Some(vcek) = vcek {
        Ok(vcek)
    } else if let Some(vlek) = vlek {
        Ok(vlek)
    } else {
        get_vcek(snp_report).context("getting vcek")
    }?;
    let certchain = get_cert_chain(&cert).context("getting cert chain")?;
    let cert = match cert {
        AmdCertType::VCEK(cert) => cert,
        AmdCertType::VLEK(cert) => cert,
    };
    let mut certchain_str = String::new();
    for cert in [cert, certchain.ask, certchain.ark] {
        let v = cert.to_pem().context("x509 to pem")?;
        certchain_str.push_str(String::from_utf8(v)?.as_str());
    }
    Ok(certchain_str)
}

pub fn fetch_cached_vcek_chain(
    snp_report: &AttestationReport,
    certs: Option<&Vec<CertTableEntry>>,
) -> Result<String, Box<dyn std::error::Error>> {
    let certchain = std::fs::read_to_string(sev::cached_chain::home().unwrap());
    let certchain = certchain.or_else(|_| {
        let path = sev::cached_chain::home().unwrap();
        match fetch_vcek_chain(snp_report, certs) {
            Ok(certchain) => {
                let mut file = std::fs::File::create(path.clone())
                    .context(format!("create {} (run mkdir manually)", path.display()))?;
                file.write_all(certchain.as_bytes())?;
                Ok(certchain)
            }
            Err(e) => Err(e.context("failed to fetch vcek chain")),
        }
    })?;
    Ok(certchain)
}
