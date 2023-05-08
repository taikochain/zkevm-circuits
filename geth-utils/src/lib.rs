//! Connection to external EVM tracer.

use core::fmt::{Display, Formatter, Result as FmtResult};
use ethers_core::types::{Block, Transaction};
use serde_json;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

extern "C" {
    fn CreateTrace(str: *const c_char) -> *const c_char;
    fn FreeString(str: *const c_char);
    fn BlockRlp(str: *const c_char) -> *const c_char;
}

pub fn block_rlp(block: &Block<Transaction>) -> Result<Vec<u8>, Error> {
    let input = serde_json::to_string(block).map_err(|e| Error::BlockRlpError(e.to_string()))?;
    let c_input = CString::new(input).expect("invalid input");
    let result = unsafe { BlockRlp(c_input.as_ptr()) };
    let c_result = unsafe { CStr::from_ptr(result) };
    let result = c_result
        .to_str()
        .expect("Error translating EVM block from library")
        .to_string();

    // We can now free the returned string (memory managed by Go)
    unsafe { FreeString(c_result.as_ptr()) };

    // Return the trace
    match result.is_empty() || result.starts_with("Failed") {
        true => Err(Error::BlockRlpError(result)),
        false => {
            let result = result.trim_start_matches("0x");
            let result = result.trim_start_matches("0X");
            hex::decode(result).map_err(|e| Error::BlockRlpError(e.to_string()))
        }
    }
}

/// Creates the trace
pub fn trace(config: &str) -> Result<String, Error> {
    // Create a string we can pass into Go
    let c_config = CString::new(config).expect("invalid config");

    // Generate the trace externally
    let result = unsafe { CreateTrace(c_config.as_ptr()) };

    // Convert the returned string to something we can use in Rust again.
    // Also make sure the returned data is copied to rust managed memory.
    let c_result = unsafe { CStr::from_ptr(result) };
    let result = c_result
        .to_str()
        .expect("Error translating EVM trace from library")
        .to_string();

    // We can now free the returned string (memory managed by Go)
    unsafe { FreeString(c_result.as_ptr()) };

    // Return the trace
    match result.is_empty() || result.starts_with("Failed") {
        true => Err(Error::TracingError(result)),
        false => Ok(result),
    }
}

/// Error type for any geth-utils related failure.
#[derive(Debug, Clone)]
pub enum Error {
    /// Error while tracing.
    TracingError(String),
    BlockRlpError(String),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{:?}", self)
    }
}

#[cfg(test)]
mod test {
    use crate::trace;

    #[test]
    fn test_trim() {
        let result = "0xx".trim_start_matches("0x");
        assert_eq!(result, "x");
    }

    #[test]
    fn valid_tx() {
        for config in [
            // Minimal call tx with gas_limit = 21000
            r#"{
                "block_constants": {
                    "gas_limit": "0x52080"
                },
                "transactions": [
                    {
                        "from": "0x00000000000000000000000000000000000000fe",
                        "to": "0x00000000000000000000000000000000000000ff",
                        "gas_limit": "0x5208"
                    }
                ]
            }"#,
            // Minimal creation tx with gas_limit = 53000
            r#"{
                "block_constants": {
                    "gas_limit": "0xcf080"
                },
                "transactions": [
                    {
                        "from": "0x00000000000000000000000000000000000000fe",
                        "gas_limit": "0xcf08"
                    }
                ]
            }"#,
            // Normal call tx with gas_limit = 21000 and gas_price = 2 Gwei
            r#"{
                "block_constants": {
                    "gas_limit": "0x52080"
                },
                "accounts": {
                    "0x00000000000000000000000000000000000000fe": {
                        "balance": "0x2632e314a000"
                    }
                },
                "transactions": [
                    {
                        "from": "0x00000000000000000000000000000000000000fe",
                        "to": "0x00000000000000000000000000000000000000ff",
                        "gas_limit": "0x5208",
                        "gas_price": "0x77359400"
                    }
                ]
            }"#,
        ] {
            assert!(trace(config).is_ok());
        }
    }

    #[test]
    fn invalid_tx() {
        for config in [
            // Insufficient gas for intrinsic usage
            r#"{
                "block_constants": {
                    "gas_limit": "0xcf080"
                },
                "transactions": [
                    {
                        "from": "0x00000000000000000000000000000000000000fe",
                        "to": "0x00000000000000000000000000000000000000ff"
                    }
                ]
            }"#,
            // Insufficient balance to buy gas
            r#"{
                "block_constants": {
                    "gas_limit": "0x52080"
                },
                "transactions": [
                    {
                        "from": "0x00000000000000000000000000000000000000fe",
                        "to": "0x00000000000000000000000000000000000000ff",
                        "gas_limit": "0x5208",
                        "gas_price": "0x1111"
                    }
                ]
            }"#,
            // Insufficient balance to do the first transfer
            r#"{
                "block_constants": {
                    "gas_limit": "0x52080"
                },
                "transactions": [
                    {
                        "from": "0x00000000000000000000000000000000000000fe",
                        "to": "0x00000000000000000000000000000000000000ff",
                        "value": "0x100",
                        "gas_limit": "0x5208"
                    }
                ]
            }"#,
        ] {
            assert!(trace(config).is_err())
        }
    }
}
