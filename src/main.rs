use maa_attest::maa::*;

fn attest_snp(
    maa: &MAA,
    reportdata: &str,
    nonce: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let maa_req = MAASnpAttestRequest::new(
        MAARuntimeData::JSON {
            data: reportdata.to_string(),
        },
        None,
        Some(nonce),
    )?;
    maa.attest_sev_snp_vm(maa_req)
}

const MAA_URL: &str = "https://maajepio.eus.attest.azure.net";
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let maa = MAA::new_verifier(MAA_URL)?;
    let token = attest_snp(&maa, "{\"runtimedata\": 1}", "nonnce")?;
    let header = jsonwebtoken::decode_header(&token)?;
    println!("token: {}", serde_json::to_value(header)?);
    let token_data = maa.verify::<serde_json::Value>(&token)?;
    println!("token_data: {}", serde_json::to_string(&token_data.claims)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_REQUEST: &str = include_str!("../test/request.json");

    fn create_maa_test_request() -> MAASnpAttestRequest {
        let report = MAASnpReport {
            SnpReport: include_bytes!("../test/SnpReport").to_vec(),
            VcekCertChain: include_str!("../test/VcekCertChain").to_string(),
        };
        let report_json = serde_json::to_string(&report).unwrap();

        MAASnpAttestRequest {
            report: report_json,
            runtimeData: MAARuntimeData::JSON {
                data: include_str!("../test/runtimeData_data").to_string(),
            },
            nonce: "nonce".to_string(),
        }
    }
    const SHARED_MAA_URL: &str = "https://sharedeus2.eus2.attest.azure.net";

    #[test]
    fn test_attest_and_verify() -> Result<(), Box<dyn std::error::Error>> {
        let maa = MAA::new_verifier(SHARED_MAA_URL)?;
        let req = create_maa_test_request();
        let token = maa.attest_sev_snp_vm(req)?;
        println!("token: {}", token);
        let token_data = maa.verify::<serde_json::Value>(&token)?;
        println!(
            "token_data: {}",
            serde_json::to_string_pretty(&token_data.claims)?
        );
        Ok(())
    }
}
