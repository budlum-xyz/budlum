#![no_main]

//! The BudL front end has never been fuzzed.
//!
//! `bud-compiler` is 3379 lines of lexer, parser, semantic analysis and
//! codegen, and every test it has feeds it a contract someone wrote by hand.
//! Nothing has ever handed it a hostile string. The compiler is not yet wired
//! into the chain, so a panic here is not a live denial of service; it is the
//! thing that has to be false *before* it is wired in, which is why the target
//! exists now rather than after.
//!
//! What this asserts: `compile` returns, for every input. `Ok` or
//! `CompileError`, never a panic, never an unwrap on a malformed parse, never
//! an index past the end of a token stream. A compiler that aborts the process
//! on bad input cannot be put behind an RPC endpoint.
//!
//! Both ISA profiles run on the same bytes. `Production` and `Experimental`
//! gate different opcode sets, so a crash reachable only under one of them is
//! a crash that a profile flag would hide.
//!
//! One thing this target will *not* report, checked before writing it: the
//! parser holds three `unreachable!()` arms, at `parser.rs` 440, 456 and 488.
//! Every one of them sits inside a `while matches!(self.peek(), ...)` whose
//! pattern list is the same as the `match` immediately below it, so the
//! unmatched arm really is unreachable and a fuzzer cannot drive it. That
//! matters because a deliberate panic reached by a fuzzer is a false positive
//! that costs triage time, and the usual advice is to audit for them first.
//! These three are sound as written; if a token is ever added to one list and
//! not the other, this target is what will find it.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Invalid UTF-8 is the lexer's problem in a different sense: `compile`
    // takes `&str`, so the host has already decided the bytes are text. Fuzz
    // the decision the compiler actually gets to make.
    let Ok(source) = std::str::from_utf8(data) else {
        return;
    };

    // A megabyte of nested braces is a parser depth question, not a soundness
    // question, and libFuzzer will happily spend the whole budget there.
    if source.len() > 64 * 1024 {
        return;
    }

    for profile in [
        bud_isa::IsaProfile::Production,
        bud_isa::IsaProfile::Experimental,
    ] {
        // The result is deliberately ignored: an error is a correct outcome
        // for almost every input here. The property under test is that the
        // call returns at all.
        let _ = bud_compiler::compile(source, profile);
    }
});
