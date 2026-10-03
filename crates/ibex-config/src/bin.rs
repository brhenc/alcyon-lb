// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

fn main() {
    let lines = ibex_config::lexer::lex(".if streq(\"$MYVAR\",value)");
    println!("{:?}", lines);
}
