mod amd_kds;
mod maa;
use maa::*;

fn attest_snp(maa : &MAA, reportdata: &str, nonce: &str) -> Result<String, Box<dyn std::error::Error>> {
    let maasnpreport = maa::gather_snp_evidence(reportdata.as_bytes())?;
    let maa_req = MAASnpAttestRequest{
        report: serde_json::to_string(&maasnpreport).unwrap(),
        runtimeData: MAARuntimeData{
            data: reportdata.to_string(),
            dataType: MAARuntimeDataType::JSON,
        },
        nonce: nonce.to_string(),
    };
    maa.attest_sev_snp_vm(maa_req)
}

const MAA_URL: &str = "https://maajepio.eus.attest.azure.net";
fn main() -> Result<(), Box<dyn std::error::Error>>{
    let maa = maa::MAA::new_verifier(MAA_URL)?;
    let token = attest_snp(&maa, "{\"runtimedata\": 1}", "nonnce")?;
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