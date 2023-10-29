//! This module generates traces by connecting to an external tracer

use eth_types::{
    geth_types::{Account, BlockConstants, Transaction},
    Address, Error, GethExecTrace, Word,
};
use serde::Serialize;
use std::collections::HashMap;

/// Configuration structure for `geth_utlis::trace`
#[derive(Debug, Default, Clone, Serialize)]
pub struct TraceConfig {
    /// chain id
    pub chain_id: Word,
    /// history hashes contains most recent 256 block hashes in history, where
    /// the lastest one is at history_hashes[history_hashes.len() - 1].
    pub history_hashes: Vec<Word>,
    /// block constants
    pub block_constants: BlockConstants,
    /// accounts
    pub accounts: HashMap<Address, Account>,
    /// transaction
    pub transactions: Vec<Transaction>,
    /// logger
    pub logger_config: LoggerConfig,
    /// taiko
    pub taiko: bool,
    /// enable invalid tx
    pub enbalbe_invalid_tx: bool,
}

/// Configuration structure for `logger.Config`
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct LoggerConfig {
    /// enable memory capture
    pub enable_memory: bool,
    /// disable stack capture
    pub disable_stack: bool,
    /// disable storage capture
    pub disable_storage: bool,
    /// enable return data capture
    pub enable_return_data: bool,
}

impl Default for LoggerConfig {
    fn default() -> Self {
        Self {
            enable_memory: false,
            disable_stack: false,
            disable_storage: false,
            enable_return_data: true,
        }
    }
}

impl LoggerConfig {
    pub fn enable_memory() -> Self {
        Self {
            enable_memory: true,
            ..Self::default()
        }
    }
}

/// Creates a trace for the specified config
pub fn trace(config: &TraceConfig) -> Result<Vec<GethExecTrace>, Error> {
    // Get the trace
    let trace_string = geth_utils::trace(&serde_json::to_string(&config).unwrap()).map_err(
        |error| match error {
            geth_utils::Error::TracingError(error) => Error::TracingError(error),
        },
    )?;

    let trace: Vec<GethExecTrace> =
        serde_json::from_str(&trace_string).map_err(Error::SerdeError)?;
    // Don't throw only for specific invalid transactions we support.

    if config.enbalbe_invalid_tx {
        for trace in trace.iter() {
            let allowed_cases = trace.return_value.starts_with("nonce too low")
                || trace.return_value.starts_with("nonce too high")
                || trace.return_value.starts_with("intrinsic gas too low")
                || trace
                    .return_value
                    .starts_with("insufficient funds for gas * price + value");
            if trace.invalid && !allowed_cases {
                return Err(Error::TracingError(trace.return_value.clone()));
            }
        }
    } else {
        for trace in trace.iter() {
            if trace.invalid {
                return Err(Error::TracingError(trace.return_value.clone()));
            }
        }
    }
    Ok(trace)
}
