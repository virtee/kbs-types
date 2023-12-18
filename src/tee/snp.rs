use crate::String;

use std::convert::TryInto;

use serde::{Deserialize, Serialize};
use serde_json::from_str;
use sev::{firmware::guest::AttestationReport, Generation};

pub enum Error {
    ReportDecode(serde_json::Error),
    GenerationDecode,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SnpAttestation {
    pub report: String,
    pub gen: String,
}

impl TryInto<(AttestationReport, Generation)> for SnpAttestation {
    type Error = Error;

    fn try_into(self) -> Result<(AttestationReport, Generation), Self::Error> {
        let report: AttestationReport = from_str(&self.report).map_err(Error::ReportDecode)?;
        let gen = match &self.gen[..] {
            "naples" => Generation::Naples,
            "rome" => Generation::Rome,
            "milan" => Generation::Milan,
            "genoa" => Generation::Genoa,
            _ => return Err(Error::GenerationDecode),
        };

        Ok((report, gen))
    }
}
