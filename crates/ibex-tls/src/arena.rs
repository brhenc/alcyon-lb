// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Ibex contributors. See LICENSE.

//! Pre-allocated zero-allocation TLS memory arena.
//!
//! Sized at proxy boot to eliminate runtime heap allocations during TLS handshakes
//! and proxy data forwarding.

use rustls::{ClientConnection, ServerConnection};
use std::fmt;

/// Maximum number of pre-allocated TLS slots supported by a single arena.
pub const MAX_TLS_SLOTS: usize = 65_536;

/// Default capacity for per-slot I/O staging buffers (16 KiB TLS max record size).
pub const DEFAULT_TLS_BUF_CAPACITY: usize = 16_384 + 512;

/// State of a TLS session within a slot.
pub enum TlsSession {
    Server(ServerConnection),
    Client(ClientConnection),
}

impl fmt::Debug for TlsSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Server(_) => write!(f, "TlsSession::Server"),
            Self::Client(_) => write!(f, "TlsSession::Client"),
        }
    }
}

/// A pre-allocated TLS connection slot.
#[derive(Debug)]
pub struct TlsSlot {
    pub slot_id: u32,
    pub in_use: bool,
    pub generation: u32,
    pub session: Option<TlsSession>,
    pub rx_buf: Vec<u8>,
    pub tx_buf: Vec<u8>,
}

impl TlsSlot {
    fn new(slot_id: u32, buf_capacity: usize) -> Self {
        Self {
            slot_id,
            in_use: false,
            generation: 0,
            session: None,
            rx_buf: Vec::with_capacity(buf_capacity),
            tx_buf: Vec::with_capacity(buf_capacity),
        }
    }

    /// Resets the slot state for reuse without deallocating internal buffer memory.
    pub fn reset(&mut self) {
        self.in_use = false;
        self.generation = self.generation.wrapping_add(1);
        self.session = None;
        self.rx_buf.clear();
        self.tx_buf.clear();
    }
}

/// Errors returned by [`TlsArena`].
#[derive(Debug, PartialEq, Eq)]
pub enum TlsArenaError {
    Exhausted(usize),
    InvalidSlot(u32),
    GenerationMismatch(u32),
}

impl fmt::Display for TlsArenaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exhausted(cap) => write!(f, "TLS arena exhausted: all {cap} slots are in use"),
            Self::InvalidSlot(id) => write!(f, "Invalid slot ID: {id}"),
            Self::GenerationMismatch(id) => write!(f, "Generation mismatch for slot ID {id}"),
        }
    }
}

impl std::error::Error for TlsArenaError {}

/// Pre-allocated arena for zero-allocation TLS session management.
#[derive(Debug)]
pub struct TlsArena {
    slots: Vec<TlsSlot>,
    free_list: Vec<u32>,
    buf_capacity: usize,
}

impl TlsArena {
    /// Creates a new TLS arena with the given slot capacity and per-slot buffer capacity.
    ///
    /// # Panics
    /// Panics if `capacity` exceeds [`MAX_TLS_SLOTS`].
    #[must_use]
    pub fn new(capacity: usize, buf_capacity: usize) -> Self {
        assert!(capacity <= MAX_TLS_SLOTS, "Capacity exceeds MAX_TLS_SLOTS");
        let mut slots = Vec::with_capacity(capacity);
        let mut free_list = Vec::with_capacity(capacity);

        for i in 0..capacity {
            let id = u32::try_from(i).unwrap_or(0);
            slots.push(TlsSlot::new(id, buf_capacity));
            free_list.push(id);
        }
        free_list.reverse();

        Self {
            slots,
            free_list,
            buf_capacity,
        }
    }

    /// Allocates a slot for a server connection.
    ///
    /// # Errors
    /// Returns [`TlsArenaError::Exhausted`] if all slots are in use.
    pub fn alloc_server(&mut self, conn: ServerConnection) -> Result<u32, TlsArenaError> {
        let slot_id = self.alloc_slot()?;
        let slot = &mut self.slots[slot_id as usize];
        slot.session = Some(TlsSession::Server(conn));
        Ok(slot_id)
    }

    /// Allocates a slot for a client connection.
    ///
    /// # Errors
    /// Returns [`TlsArenaError::Exhausted`] if all slots are in use.
    pub fn alloc_client(&mut self, conn: ClientConnection) -> Result<u32, TlsArenaError> {
        let slot_id = self.alloc_slot()?;
        let slot = &mut self.slots[slot_id as usize];
        slot.session = Some(TlsSession::Client(conn));
        Ok(slot_id)
    }

    fn alloc_slot(&mut self) -> Result<u32, TlsArenaError> {
        let slot_id = self
            .free_list
            .pop()
            .ok_or(TlsArenaError::Exhausted(self.slots.len()))?;
        let slot = &mut self.slots[slot_id as usize];
        slot.in_use = true;
        slot.rx_buf.clear();
        slot.tx_buf.clear();
        Ok(slot_id)
    }

    /// Frees an allocated slot by ID, recycling it into the free list.
    ///
    /// # Errors
    /// Returns [`TlsArenaError::InvalidSlot`] if the slot ID is invalid or not in use.
    pub fn free(&mut self, slot_id: u32) -> Result<(), TlsArenaError> {
        let idx = slot_id as usize;
        if idx >= self.slots.len() {
            return Err(TlsArenaError::InvalidSlot(slot_id));
        }
        if !self.slots[idx].in_use {
            return Err(TlsArenaError::InvalidSlot(slot_id));
        }
        self.slots[idx].reset();
        self.free_list.push(slot_id);
        Ok(())
    }

    /// Returns a reference to a slot if currently in use.
    #[must_use]
    pub fn get(&self, slot_id: u32) -> Option<&TlsSlot> {
        self.slots.get(slot_id as usize).filter(|s| s.in_use)
    }

    /// Returns a mutable reference to a slot if currently in use.
    pub fn get_mut(&mut self, slot_id: u32) -> Option<&mut TlsSlot> {
        let slot = self.slots.get_mut(slot_id as usize)?;
        if slot.in_use {
            Some(slot)
        } else {
            None
        }
    }

    /// Returns the number of currently active slots.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.slots.len() - self.free_list.len()
    }

    /// Returns the total capacity of the arena.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    /// Returns whether all slots are free.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.free_list.len() == self.slots.len()
    }

    /// Returns the buffer capacity configured per slot.
    #[must_use]
    pub fn buf_capacity(&self) -> usize {
        self.buf_capacity
    }
}
