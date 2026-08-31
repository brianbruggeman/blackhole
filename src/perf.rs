//! Default-off copy-boundary counters for the performance gate.

use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum Boundary {
    PolicyCanonicalize = 0,
    BorrowedToOwned = 1,
    TcpFrameBuffer = 2,
    EncodeOutput = 3,
    TransportWrite = 4,
}

const BOUNDARY_COUNT: usize = 5;
static COPY_BYTES: [AtomicU64; BOUNDARY_COUNT] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    pub policy_canonicalize: u64,
    pub borrowed_to_owned: u64,
    pub tcp_frame_buffer: u64,
    pub encode_output: u64,
    pub transport_write: u64,
}

pub fn record_copy(boundary: Boundary, bytes: usize) {
    COPY_BYTES[boundary as usize].fetch_add(bytes as u64, Ordering::Relaxed);
}

#[must_use]
pub fn snapshot() -> Snapshot {
    Snapshot {
        policy_canonicalize: COPY_BYTES[Boundary::PolicyCanonicalize as usize]
            .load(Ordering::Relaxed),
        borrowed_to_owned: COPY_BYTES[Boundary::BorrowedToOwned as usize].load(Ordering::Relaxed),
        tcp_frame_buffer: COPY_BYTES[Boundary::TcpFrameBuffer as usize].load(Ordering::Relaxed),
        encode_output: COPY_BYTES[Boundary::EncodeOutput as usize].load(Ordering::Relaxed),
        transport_write: COPY_BYTES[Boundary::TransportWrite as usize].load(Ordering::Relaxed),
    }
}

pub fn reset() {
    for counter in &COPY_BYTES {
        counter.store(0, Ordering::Relaxed);
    }
}
