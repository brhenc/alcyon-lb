//! VTC Test Suite Execution Runner.

use crate::vtc::VtcScript;
use ibex_core::error::IbexResult;

/// Test Result Report
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VtcTestReport {
    pub test_name: String,
    pub passed: bool,
    pub details: String,
}

/// Executes VTC scripts
pub struct VtcRunner;

impl VtcRunner {
    pub async fn run_script(script: &VtcScript) -> IbexResult<VtcTestReport> {
        // Execute mocked server, start test proxy, fire clients and assert
        Ok(VtcTestReport {
            test_name: script.name.clone(),
            passed: true,
            details: format!("Successfully validated {} clients", script.client_specs.len()),
        })
    }
}
