// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/acl.c, src/sample.c and src/pattern.c.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The load-time check of `-m <method>` against the type of the expression
//! (`parse_acl_expr`, `smp_expr_output_type`, `sample_casts`, `pat_match_types`).
//!
//! `HAProxy` refuses "matching method 'ip' cannot be used with fetch keyword 'always_true'"
//! when no cast exists from the expression's output type to the type the method matches on.
//! An expression whose type is `any` (`var()`) casts to everything, and so does `-m found`.

use crate::registry::sample_registry;
use crate::sample::{SampleType, TypeSpec};

/// `SMP_T_*`, in the order of the columns of `sample_casts`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ty {
    Any,
    Bool,
    Sint,
    Addr,
    Ipv4,
    Ipv6,
    Str,
    Bin,
    Meth,
}

/// What `sample_casts[from][to]` holds: `c_none`, a real cast, or `NULL`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Cast {
    None,
    Cast,
    No,
}

const fn idx(t: Ty) -> usize {
    match t {
        Ty::Any => 0,
        Ty::Bool => 1,
        Ty::Sint => 2,
        Ty::Addr => 3,
        Ty::Ipv4 => 4,
        Ty::Ipv6 => 5,
        Ty::Str => 6,
        Ty::Bin => 7,
        Ty::Meth => 8,
    }
}

/// `sample_casts` without its `SAME` row and column (`N` = `c_none`, `C` = a cast, `X` = `NULL`).
const CASTS: [[Cast; 9]; 9] = {
    use Cast::{Cast as C, No as X, None as N};
    [
        //  ANY BOOL SINT ADDR IPV4 IPV6 STR BIN METH
        [N, C, C, C, C, C, C, C, C], // ANY
        [N, N, N, X, X, X, C, C, X], // BOOL
        [N, N, N, C, C, C, C, C, X], // SINT
        [N, X, X, C, C, C, C, C, X], // ADDR
        [N, X, C, N, N, C, C, C, X], // IPV4
        [N, X, X, N, C, N, C, C, X], // IPV6
        [N, C, C, C, C, C, N, N, C], // STR
        [N, X, X, X, X, X, C, N, C], // BIN
        [N, X, X, X, X, X, C, C, N], // METH
    ]
};

fn cast(from: Ty, to: Ty) -> Cast {
    CASTS[idx(from)][idx(to)]
}

const fn of_sample_type(t: SampleType) -> Ty {
    match t {
        SampleType::Bool => Ty::Bool,
        SampleType::Sint => Ty::Sint,
        SampleType::Ipv4 => Ty::Ipv4,
        SampleType::Ipv6 => Ty::Ipv6,
        SampleType::Str => Ty::Str,
        SampleType::Bin => Ty::Bin,
        SampleType::Meth => Ty::Meth,
    }
}

/// The type `HAProxy` declares for a fetch where Ibex's registry says otherwise (`haproxy
/// -dKsmp`, 3.5-dev8): `ADDR` is not a type of Ibex's samples, `var` and the `sc*_key` fetches
/// are `ANY`.
fn fetch_type_override(name: &str) -> Option<Ty> {
    match name {
        "bc_dst" | "dst" | "fc_dst" | "fc_src" | "hdr_ip" | "req.hdr_ip" | "res.hdr_ip" | "shdr_ip" | "src" => Some(Ty::Addr),
        "var" | "sc_key" | "sc0_key" | "sc1_key" | "sc2_key" => Some(Ty::Any),
        "fc_pp_tlv" | "ssl_fc_cipherlist_bin" | "ssl_fc_ecformats_bin" | "ssl_fc_eclist_bin" | "ssl_fc_extlist_bin" => {
            Some(Ty::Str)
        }
        "req.hdrs" | "res.hdrs" => Some(Ty::Bin),
        _ => None,
    }
}

/// The input and output types `HAProxy` declares for a converter where Ibex's registry says
/// otherwise (`haproxy -dKcnv`).
fn conv_type_override(name: &str) -> Option<(Ty, Ty)> {
    match name {
        "mqtt_field_value" => Some((Ty::Bin, Ty::Str)),
        "protobuf" | "ungrpc" => Some((Ty::Bin, Ty::Bin)),
        "rfc7239_n2nn" | "rfc7239_n2np" => Some((Ty::Str, Ty::Any)),
        _ => None,
    }
}

/// The input type and the output type of a converter, `None` for `SMP_T_SAME`.
fn conv_types(name: &str) -> Option<(Ty, Option<Ty>)> {
    if let Some((i, o)) = conv_type_override(name) {
        return Some((i, Some(o)));
    }
    let reg = sample_registry();
    let (i, o) = reg
        .get_converter(name)
        .map(|c| (c.in_type, c.out_type))
        .or_else(|| reg.get_ctx_converter(name).map(|c| (c.in_type, c.out_type)))?;
    let spec = |s: TypeSpec| match s {
        TypeSpec::Exact(t) => Some(of_sample_type(t)),
        TypeSpec::Any => Some(Ty::Any),
        TypeSpec::Addr => Some(Ty::Addr),
        TypeSpec::Same => None,
    };
    Some((spec(i).unwrap_or(Ty::Any), spec(o)))
}

/// `smp_expr_output_type`: the type of the expression, `None` when a name is not one the
/// registry knows (the caller refuses those elsewhere).
#[must_use]
pub fn expr_output_type(fetch: &str, converters: &[(String, Vec<String>)]) -> Option<Ty> {
    let mut next = Ty::Any;
    for (name, _) in converters.iter().rev() {
        let (in_ty, out_ty) = conv_types(name)?;
        if let Some(cur) = out_ty {
            return Some(if cast(cur, next) == Cast::None { cur } else { next });
        }
        // A converter that keeps its input's type is skipped, unless switching to the next
        // type is not free: then the sample is of that type.
        if cast(Ty::Any, next) != Cast::None {
            return Some(next);
        }
        next = in_ty;
    }
    let cur = fetch_type_override(fetch).or_else(|| sample_registry().get_fetch(fetch).map(|f| of_sample_type(f.out_type)))?;
    Some(if cast(cur, next) == Cast::None { cur } else { next })
}

/// `pat_match_types` for a method name known to `HAProxy`: `None` for `found`, which any type
/// takes, and for names that are not methods.
fn match_type(method: &str) -> Option<Ty> {
    match method {
        "bool" | "int" => Some(Ty::Sint),
        "ip" => Some(Ty::Addr),
        "bin" => Some(Ty::Bin),
        "len" | "str" | "beg" | "sub" | "dir" | "dom" | "end" | "reg" | "regm" => Some(Ty::Str),
        _ => None,
    }
}

/// `parse_acl_expr`'s refusal of `-m <method>` for an expression of type `ty`; `kw` is the
/// fetch keyword as written.
///
/// # Errors
/// `HAProxy`'s text, when no cast exists.
pub fn check_match_method(method: &str, kw: &str, ty: Ty) -> Result<(), String> {
    match match_type(method) {
        Some(want) if cast(ty, want) == Cast::No => {
            Err(format!("matching method '{method}' cannot be used with fetch keyword '{kw}'"))
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conv(names: &[&str]) -> Vec<(String, Vec<String>)> {
        names.iter().map(|n| ((*n).to_string(), Vec::new())).collect()
    }

    #[test]
    fn types_follow_the_last_converter_and_the_fetch() {
        assert_eq!(expr_output_type("always_true", &[]), Some(Ty::Bool));
        assert_eq!(expr_output_type("src", &[]), Some(Ty::Addr));
        assert_eq!(expr_output_type("var", &[]), Some(Ty::Any));
        assert_eq!(expr_output_type("str", &conv(&["b64dec"])), Some(Ty::Bin));
        assert_eq!(expr_output_type("int", &conv(&["hex"])), Some(Ty::Str));
        assert_eq!(expr_output_type("no_such_fetch", &[]), None);
    }

    #[test]
    fn the_table_refuses_what_there_is_no_cast_for() {
        for (m, ty) in [("ip", Ty::Bool), ("int", Ty::Ipv6), ("int", Ty::Bin), ("bool", Ty::Meth), ("ip", Ty::Bin), ("int", Ty::Addr)] {
            assert!(check_match_method(m, "k", ty).is_err(), "{m} {ty:?}");
        }
        for (m, ty) in [("found", Ty::Bin), ("bin", Ty::Bool), ("ip", Ty::Any), ("int", Ty::Any), ("str", Ty::Meth), ("ip", Ty::Str)] {
            assert!(check_match_method(m, "k", ty).is_ok(), "{m} {ty:?}");
        }
    }
}
