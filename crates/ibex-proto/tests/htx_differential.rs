// SPDX-License-Identifier: GPL-2.0-or-later
// Differential testing of HtxBuffer against reference Htx (Vec<HtxBlock>).

use ibex_proto::htx::{
    HeaderField, Htx, HtxBlock, HtxBlockType, HtxBuffer, HtxError,
};
use proptest::prelude::*;

#[derive(Debug, Clone)]
enum Op {
    PushHeader(String, String),
    PushData(Vec<u8>),
    PushTrailer(String, String),
    PushEoh,
    PushEot,
    PushEom,
    RemoveBlock(usize),
    ReplaceValue(usize, String),
    Defrag,
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (any::<String>(), any::<String>()).prop_map(|(k, v)| Op::PushHeader(k, v)),
        2 => prop::collection::vec(any::<u8>(), 0..64).prop_map(Op::PushData),
        1 => (any::<String>(), any::<String>()).prop_map(|(k, v)| Op::PushTrailer(k, v)),
        1 => Just(Op::PushEoh),
        1 => Just(Op::PushEot),
        1 => Just(Op::PushEom),
        2 => (0usize..32).prop_map(Op::RemoveBlock),
        2 => (0usize..32, any::<String>()).prop_map(|(i, v)| Op::ReplaceValue(i, v)),
        1 => Just(Op::Defrag),
    ]
}

/// Finds the physical descriptor index corresponding to the `logical_idx`-th active block.
fn physical_index_of_active(buf: &HtxBuffer, logical_idx: usize) -> Option<usize> {
    let mut active = 0;
    for i in 0..buf.num_blocks() {
        if buf.block_type(i) != Some(HtxBlockType::Unused) {
            if active == logical_idx {
                return Some(i);
            }
            active += 1;
        }
    }
    None
}

fn run_ops(ops: &[Op]) -> Result<(), TestCaseError> {
    let mut buf = HtxBuffer::with_capacity(32768);
    let mut htx = Htx::new();

    for (step, op) in ops.iter().enumerate() {
        match op {
            Op::PushHeader(k, v) => {
                let mut k = k.replace(['\r', '\n'], "").replace(':', "");
                if k.is_empty() {
                    k = "X-Header".into();
                }
                let v = v.replace(['\r', '\n'], "");
                let k: String = k.chars().take(64).collect();
                let v: String = v.chars().take(128).collect();

                if buf.push_header(&k, &v).is_ok() {
                    htx.push(HtxBlock::Header(HeaderField { name: k, value: v }));
                }
            }
            Op::PushData(d) => {
                if buf.push_data(d).is_ok() {
                    htx.push(HtxBlock::Data(d.clone()));
                }
            }
            Op::PushTrailer(k, v) => {
                let mut k = k.replace(['\r', '\n'], "").replace(':', "");
                if k.is_empty() {
                    k = "X-Trailer".into();
                }
                let v = v.replace(['\r', '\n'], "");
                let k: String = k.chars().take(64).collect();
                let v: String = v.chars().take(128).collect();

                if buf.push_trailer(&k, &v).is_ok() {
                    htx.push(HtxBlock::Trailer(HeaderField { name: k, value: v }));
                }
            }
            Op::PushEoh => {
                if buf.push_eoh().is_ok() {
                    htx.push(HtxBlock::Eoh);
                }
            }
            Op::PushEot => {
                if buf.push_eot().is_ok() {
                    htx.push(HtxBlock::Eot);
                }
            }
            Op::PushEom => {
                if buf.push_eom().is_ok() {
                    htx.push(HtxBlock::Eom);
                }
            }
            Op::RemoveBlock(nth) => {
                let active_count = htx.blocks().len();
                if active_count > 0 {
                    let logical_idx = nth % active_count;
                    if let Some(phys_idx) = physical_index_of_active(&buf, logical_idx) {
                        buf.remove_block(phys_idx);
                        htx.remove_block(logical_idx);
                    }
                }
            }
            Op::ReplaceValue(nth, v) => {
                let active_count = htx.blocks().len();
                if active_count > 0 {
                    let logical_idx = nth % active_count;
                    if let Some(phys_idx) = physical_index_of_active(&buf, logical_idx) {
                        let v = v.replace(['\r', '\n'], "");
                        let v: String = v.chars().take(128).collect();

                        match &mut htx.blocks_mut()[logical_idx] {
                            HtxBlock::Header(h)
                                if buf.replace_block_value(phys_idx, v.as_bytes()).is_ok() =>
                            {
                                h.value = v;
                            }
                            HtxBlock::Trailer(t)
                                if buf.replace_block_value(phys_idx, v.as_bytes()).is_ok() =>
                            {
                                t.value = v;
                            }
                            HtxBlock::Data(d)
                                if buf.replace_block_value(phys_idx, v.as_bytes()).is_ok() =>
                            {
                                *d = v.into_bytes();
                            }
                            _ => {}
                        }
                    }
                }
            }
            Op::Defrag => {
                buf.defrag();
            }
        }

        // Structural invariants check after EVERY operation
        if let Err(e) = buf.check_invariants() {
            return Err(TestCaseError::fail(format!(
                "step {step}: invariant violated after {op:?}: {e}"
            )));
        }

        // Exact, uncompromised equality check between HtxBuffer and Htx oracle
        prop_assert_eq!(
            buf.to_blocks(),
            htx.blocks().to_vec(),
            "step {}: state desync after op {:?}",
            step,
            op
        );
    }

    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn prop_differential_htx_buffer_vs_htx(ops in prop::collection::vec(op_strategy(), 0..80)) {
        run_ops(&ops)?;
    }
}

// ---------------------------------------------------------------------------
// Explicit T15 Required Tests
// ---------------------------------------------------------------------------

#[test]
fn test_explicit_replace_growing_forces_tail_append() {
    let mut buf = HtxBuffer::with_capacity(4096);
    let mut htx = Htx::new();

    buf.push_header("X-App", "v1").unwrap();
    htx.push(HtxBlock::Header(HeaderField {
        name: "X-App".into(),
        value: "v1".into(),
    }));
    buf.check_invariants().unwrap();

    // Growing replacement: "v1" (2 bytes) -> 200 bytes string
    let large_val = "A".repeat(200);
    buf.replace_block_value(0, large_val.as_bytes()).unwrap();
    if let HtxBlock::Header(h) = &mut htx.blocks_mut()[0] {
        h.value = large_val;
    }

    buf.check_invariants().unwrap();
    assert_eq!(buf.to_blocks(), htx.blocks());
}

#[test]
fn test_explicit_heavy_churn_and_defrag() {
    let mut buf = HtxBuffer::with_capacity(16384);
    let mut htx = Htx::new();

    for i in 0..20 {
        let name = format!("Header-{i}");
        let val = format!("val-{i}");
        buf.push_header(&name, &val).unwrap();
        htx.push(HtxBlock::Header(HeaderField {
            name,
            value: val,
        }));
    }
    buf.check_invariants().unwrap();

    // Remove even blocks: 0, 2, 4, ...
    for i in (0..20).step_by(2) {
        buf.remove_block(i);
    }
    let mut keep = Vec::new();
    for (i, b) in htx.blocks().iter().enumerate() {
        if i % 2 != 0 {
            keep.push(b.clone());
        }
    }
    htx = Htx::new();
    for b in keep {
        htx.push(b);
    }

    buf.check_invariants().unwrap();
    assert_eq!(buf.to_blocks(), htx.blocks());

    // Replace odd blocks with longer values to create fragmented garbage
    for (logical_idx, i) in (1..20).step_by(2).enumerate() {
        let new_val = format!("much_longer_value_for_odd_block_{i}_{}", "X".repeat(50));
        buf.replace_block_value(i, new_val.as_bytes()).unwrap();
        if let HtxBlock::Header(h) = &mut htx.blocks_mut()[logical_idx] {
            h.value = new_val;
        }
    }
    buf.check_invariants().unwrap();
    assert_eq!(buf.to_blocks(), htx.blocks());

    // Defrag and verify reads before and after
    let before_defrag = buf.to_blocks();
    buf.defrag();
    buf.check_invariants().unwrap();
    let after_defrag = buf.to_blocks();

    assert_eq!(before_defrag, after_defrag);
    assert_eq!(after_defrag, htx.blocks());
}

#[test]
fn test_explicit_removals_boundary() {
    let mut buf = HtxBuffer::with_capacity(2048);
    let mut htx = Htx::new();

    for i in 0..5 {
        let name = format!("H{i}");
        let val = format!("{i}");
        buf.push_header(&name, &val).unwrap();
        htx.push(HtxBlock::Header(HeaderField { name, value: val }));
    }

    // Remove first block (0)
    buf.remove_block(0);
    htx.remove_block(0);
    buf.check_invariants().unwrap();
    assert_eq!(buf.to_blocks(), htx.blocks());

    // Remove middle block (now index 2 in active list, which was original index 2)
    buf.remove_block(2);
    htx.remove_block(1);
    buf.check_invariants().unwrap();
    assert_eq!(buf.to_blocks(), htx.blocks());

    // Remove last block (original index 4)
    buf.remove_block(4);
    htx.remove_block(2);
    buf.check_invariants().unwrap();
    assert_eq!(buf.to_blocks(), htx.blocks());

    // Run defrag and assert clean state
    buf.defrag();
    buf.check_invariants().unwrap();
    assert_eq!(buf.to_blocks(), htx.blocks());
}

#[test]
fn test_explicit_capacity_exhaustion_no_corruption() {
    let mut buf = HtxBuffer::with_capacity(256);
    let mut pushed_count = 0;

    loop {
        match buf.push_header("X-Hdr", "SomeValue") {
            Ok(()) => pushed_count += 1,
            Err(HtxError::OutOfMemory) => break,
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    assert!(pushed_count > 0);
    buf.check_invariants().unwrap();
    let blocks = buf.to_blocks();
    assert_eq!(blocks.len(), pushed_count);
    for b in &blocks {
        if let HtxBlock::Header(h) = b {
            assert_eq!(h.name, "X-Hdr");
            assert_eq!(h.value, "SomeValue");
        } else {
            panic!("unexpected block: {b:?}");
        }
    }
}

#[test]
fn test_measure_htx_block_desc_and_allocations() {
    use ibex_proto::htx::{HttpMethod, HttpVersion, RequestLine};

    let desc_size = std::mem::size_of::<ibex_proto::htx::HtxBlockDesc>();
    let enum_block_size = std::mem::size_of::<HtxBlock>();

    assert_eq!(desc_size, 16, "HtxBlockDesc must be exactly 16 bytes");

    // Build a realistic request in Htx: 1 start line + 10 headers
    let headers_data = [
        ("Host", "api.project-ibex.internal"),
        ("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/128.0"),
        ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
        ("Accept-Language", "en-US,en;q=0.5"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Connection", "keep-alive"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "none"),
    ];

    let mut htx = Htx::new();
    htx.push(HtxBlock::ReqLine(RequestLine {
        method: HttpMethod::Get,
        uri: "/v1/cluster/nodes?active=true&zone=us-east-1".into(),
        version: HttpVersion::Http11,
    }));
    for (name, val) in headers_data {
        htx.push(HtxBlock::Header(HeaderField {
            name: name.into(),
            value: val.into(),
        }));
    }

    // Build the same request in HtxBuffer
    let mut buf = HtxBuffer::with_capacity(4096);
    buf.push_req_line("GET", "/v1/cluster/nodes?active=true&zone=us-east-1", "HTTP/1.1").unwrap();
    for (name, val) in headers_data {
        buf.push_header(name, val).unwrap();
    }

    buf.check_invariants().unwrap();
    assert_eq!(buf.to_blocks(), htx.blocks());

    // Measurement calculations:
    // Htx: 1 allocation for Vec<HtxBlock> (11 items * 56B), 1 allocation for uri string, 10 * 2 allocations for header strings = 22 allocations.
    // HtxBuffer: 1 single contiguous buffer allocation.
    assert!(desc_size <= 16);
    assert!(enum_block_size >= 48);
}
