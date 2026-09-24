fn main() {
    let lines = ibex_config::lexer::lex(".if streq(\"$MYVAR\",value)");
    println!("{:?}", lines);
}
