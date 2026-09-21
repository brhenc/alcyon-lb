//! HAProxy Native HTTP Transfer eXchange (HTX) representation in safe Rust.

pub mod parser;

use ibex_core::error::{IbexError, IbexResult};

/// HTX Block Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HtxBlockType {
    ReqStartLine, // Request start line (method, uri, version)
    ResStartLine, // Response start line (version, status, reason)
    Header,       // Header name and value
    Body,         // Body data chunk
    Trailer,      // Trailer header
    EndOfMessage, // End of message marker
}

/// HTX Block Descriptor
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HtxBlock {
    pub blk_type: HtxBlockType,
    pub offset: usize,
    pub length: usize,
    pub aux: u32, // Auxiliary field (e.g. status code or header name length)
}

/// HTX Buffer holding blocks and contiguous payload data
#[derive(Debug, Clone, Default)]
pub struct HtxBuffer {
    pub data: Vec<u8>,
    pub blocks: Vec<HtxBlock>,
}

impl HtxBuffer {
    /// Creates a new HTX buffer with pre-allocated capacity.
    pub fn with_capacity(data_cap: usize, blocks_cap: usize) -> Self {
        Self {
            data: Vec::with_capacity(data_cap),
            blocks: Vec::with_capacity(blocks_cap),
        }
    }

    /// Resets the buffer for reuse (zero-allocation).
    pub fn reset(&mut self) {
        self.data.clear();
        self.blocks.clear();
    }

    /// Appends a raw slice to the data buffer, returning its offset.
    pub fn push_data(&mut self, bytes: &[u8]) -> usize {
        let offset = self.data.len();
        self.data.extend_from_slice(bytes);
        offset
    }

    /// Appends an HTX block.
    pub fn push_block(&mut self, blk_type: HtxBlockType, offset: usize, length: usize, aux: u32) {
        self.blocks.push(HtxBlock {
            blk_type,
            offset,
            length,
            aux,
        });
    }

    /// Retrieves data slice for a block.
    pub fn get_block_data(&self, blk: &HtxBlock) -> IbexResult<&[u8]> {
        let end = blk.offset.saturating_add(blk.length);
        if end > self.data.len() {
            return Err(IbexError::Parser("Block data out of bounds".into()));
        }
        Ok(&self.data[blk.offset..end])
    }
}
