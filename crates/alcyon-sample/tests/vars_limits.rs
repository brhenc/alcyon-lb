// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Own binary: `tune.vars.*-max-size` are process-wide limits, and every other test's variables
// would be counted against them.

//! The accounting of `tune.vars.*` (`vars::admit`), at its edges: what a refusal leaves behind
//! (a string that does not fit turns the variable into the bool its integer, bool or address
//! held, T364 Q1), how `bin` and method values are sized, and which scopes count where.

use alcyon_proto::htx::HttpMethod;
use alcyon_sample::vars::{self, In, VarStore, VAR_STRUCT_COST};
use alcyon_sample::Sample;
use std::net::Ipv4Addr;

#[test]
fn limits_refuse_what_does_not_fit_and_leave_the_old_value_as_a_bool() {
    assert_eq!(VAR_STRUCT_COST, 88);

    // check scope: 2 variables of 88 bytes fit 200, a third does not.
    vars::set_limits(0, 0, 0, 0, 0, 200);
    let mut map = VarStore::new();
    vars::set_in(&mut map, "check.a", In::Owned(Sample::Sint(1)));
    vars::set_in(&mut map, "check.b", In::Owned(Sample::Sint(2)));
    vars::set_in(&mut map, "check.c", In::Owned(Sample::Sint(3)));
    assert!(map.contains_key("check.a") && map.contains_key("check.b"));
    assert!(!map.contains_key("check.c"), "a third check variable is over check-max-size");

    // The other scopes and value kinds are counted when the next one is set: a `sess.` variable,
    // a `bin`, a method that is not a known one, and a name in no scope that counts.
    vars::set_limits(0, 0, 100_000, 0, 0, 0);
    let mut map = VarStore::new();
    vars::set_in(&mut map, "sess.s", In::Owned(Sample::Sint(1)));
    vars::set_in(&mut map, "sess.bin", In::Owned(Sample::Bin(vec![1, 2, 3, 4])));
    vars::set_in(&mut map, "sess.meth", In::Owned(Sample::Meth(HttpMethod::Other("FOOBAR".into()))));
    vars::set_in(&mut map, "check.k", In::Owned(Sample::Sint(1)));
    vars::set_in(&mut map, "foo.bar", In::Owned(Sample::Sint(1)));
    vars::set_in(&mut map, "sess.last", In::Owned(Sample::Sint(1)));
    assert_eq!(map.entries().len(), 6, "all fit 100000 bytes");
    // 'sess.s' 88 + bin 92 + meth 94 + check 88 (also in sess) + last 88 = 450; a string of 100 000
    // does not fit and sess.bin keeps its place; a bin of 1 byte more than it held fits.
    vars::set_in(&mut map, "sess.s", In::Owned(Sample::Str("x".repeat(100_000))));
    assert_eq!(map.get("sess.s"), Some(Sample::Bool(true)), "an integer 1 that a string did not replace is true");

    // proc scope: 200 bytes; a bool, an address and an integer 0 stay as booleans.
    vars::set_limits(0, 200, 0, 0, 0, 0);
    vars::set_proc("proc.a", Sample::Bool(true));
    vars::set_proc("proc.b", Sample::Ipv4(Ipv4Addr::new(1, 2, 3, 4)));
    vars::set_proc("proc.c", Sample::Sint(3));
    assert_eq!(vars::get_proc("proc.c"), None, "a third proc variable is over proc-max-size");
    let long = || Sample::Str("y".repeat(100));
    vars::set_proc("proc.a", long());
    vars::set_proc("proc.b", long());
    assert_eq!(vars::get_proc("proc.a"), Some(Sample::Bool(true)));
    assert_eq!(vars::get_proc("proc.b"), Some(Sample::Bool(true)));
    vars::set_proc("proc.b", Sample::Ipv4(Ipv4Addr::UNSPECIFIED));
    vars::set_proc("proc.b", long());
    assert_eq!(vars::get_proc("proc.b"), Some(Sample::Bool(false)), "0.0.0.0 is false");

    // A stream variable with the limits on is counted in the thread's map.
    vars::set_limits(0, 0, 0, 100, 0, 0);
    vars::set("txn.a", Sample::Sint(1));
    vars::set("txn.b", Sample::Sint(1));
    assert_eq!(vars::get("txn.a"), Some(Sample::Sint(1)));
    assert_eq!(vars::get("txn.b"), None, "txn-max-size 100 holds one");

    vars::unset_proc_var("proc.a");
    assert_eq!(vars::get_proc("proc.a"), None);
    vars::set_limits(0, 0, 0, 0, 0, 0);

    // The converter arguments naming a variable, cast to the type asked for.
    vars::set_proc_var("proc.n", "42".into());
    assert_eq!(vars::var_arg_int("proc.n"), Some(42));
    assert_eq!(vars::var_arg_str("proc.n"), Some("42".into()));
    assert_eq!(vars::var_arg_bin("proc.n"), Some(b"42".to_vec()));
    assert_eq!(vars::var_arg_int("proc.nothing"), None);
    assert_eq!(vars::var_arg_str("proc.nothing"), None);
    assert_eq!(vars::var_arg_bin("proc.nothing"), None);

    a_text_stored_from_bytes_obeys_the_limits();
}

/// R4: a text stored from its bytes (`VarRef::store_smp`) is counted as the text stored from a
/// `Sample` is: refused when the variable's struct does not fit, a `bool` when its bytes do not.
/// Run by the test above, which owns the process-wide limits while it runs.
fn a_text_stored_from_bytes_obeys_the_limits() {
    use alcyon_sample::Smp;
    let long = "z".repeat(100);

    vars::set_limits(0, 0, 0, 0, 0, 200);
    let mut map = VarStore::new();
    for name in ["check.r4a", "check.r4b", "check.r4c"] {
        vars::VarRef::resolve(name).store_smp(&mut map, Smp::str(b"ab"));
    }
    assert_eq!(map.get("check.r4a"), Some(Sample::Str("ab".into())));
    assert!(map.get("check.r4c").is_none(), "a third check variable does not fit check-max-size 200");

    vars::VarRef::resolve("check.r4a").store_smp(&mut map, Smp::str(long.as_bytes()));
    assert_eq!(map.get("check.r4a"), Some(Sample::Bool(false)), "a text too long for the limit leaves a bool, as `set` does");
    vars::set_limits(0, 0, 0, 0, 0, 0);
}
