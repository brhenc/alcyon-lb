//! # `ibex-parser`
//!
//! Dual HTTP Parser engine featuring:
//! - Pure safe Rust HAProxy HTX (HTTP Transfer eXchange) parser & ring-buffer stream blocks.
//! - Pingora HTTP parser adapter.
//! - SIMD-accelerated delimiter scanning.
//! - Dynamic runtime parser switcher allowing hot switching per request or route.

pub mod htx;
pub mod pingora_adapter;
pub mod simd;
pub mod switcher;

pub use htx::parser::HtxParser;
pub use htx::{HtxBlock, HtxBlockType, HtxBuffer};
pub use pingora_adapter::{ParsedHttpRequest, PingoraHttpParser};
pub use simd::SimdScanner;
pub use switcher::{DynamicParserSwitcher, ParserEngineKind, UnifiedHttpRequest};
