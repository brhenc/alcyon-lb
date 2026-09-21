use thiserror::Error;

/// Core result type for all Ibex operations.
pub type IbexResult<T> = Result<T, IbexError>;

/// Root error enumeration for Ibex components.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum IbexError {
    #[error("Capacity exceeded: requested {requested}, capacity {capacity}")]
    CapacityExceeded { requested: usize, capacity: usize },

    #[error("Out of preallocated memory in arena (needed: {needed} bytes, remaining: {remaining} bytes)")]
    OutOfMemory { needed: usize, remaining: usize },

    #[error("Object pool exhausted (max capacity: {capacity})")]
    PoolExhausted { capacity: usize },

    #[error("Loop bound limit exceeded (max: {max_iterations})")]
    LoopBoundExceeded { max_iterations: usize },

    #[error("Assertion violation: {condition} at {location}")]
    AssertionFailed {
        condition: &'static str,
        location: &'static str,
    },

    #[error("Parser error: {0}")]
    Parser(String),

    #[error("Config syntax error: {0}")]
    Config(String),

    #[error("Stick table error: {0}")]
    StickTable(String),

    #[error("Peers protocol error: {0}")]
    Peers(String),

    #[error("I/O error: {0}")]
    Io(String),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("Invalid state: {0}")]
    InvalidState(String),
}
