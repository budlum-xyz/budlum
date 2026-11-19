//! Interpreter compatibility and determinism coverage for the pinned `wasmi`.
//!
//! Every module here is compiled through the engine the worker actually builds
//! (`build_wasm_engine`: floats off, fuel metering on), so a miscompilation shows
//! up under the same configuration that runs contracts.
//!
//! The first three cases are minimal re-creations of the upstream regression
//! shapes that `wasmi` 2.0.1 gets wrong and 2.0.2 fixes; they fail on the old pin
//! and pass on the new one. The rest pin the surrounding behaviour (tail-called
//! host-trap resumption, fuel determinism, refusal of floating point) so that a
//! version bump cannot quietly change it.

use budlum_ee_wasm::build_wasm_engine;
use wasmi::{
    Engine, Error as WasmiError, Instance, Linker, Module, Store, TypedResumableCall, Val,
};

/// Fuel granted to a test call: the worker always sets a budget before invoking.
const TEST_FUEL: u64 = 500_000_000;

/// A store with the worker's fuel metering switched on.
fn funded_store(engine: &Engine) -> Store<()> {
    let mut store = Store::new(engine, ());
    if store.set_fuel(TEST_FUEL).is_err() {
        panic!("the worker engine must keep fuel metering enabled");
    }
    store
}

fn compile(engine: &Engine, wat_src: &str) -> Module {
    let Ok(bytes) = wat::parse_str(wat_src) else {
        panic!("test module must assemble");
    };
    match Module::new(engine, &bytes) {
        Ok(module) => module,
        Err(err) => panic!("test module must validate: {err}"),
    }
}

/// Instantiates a module in a funded store and returns both.
fn instantiate(engine: &Engine, module: &Module) -> (Store<()>, Instance) {
    let mut store = funded_store(engine);
    let Ok(instance) = Linker::new(engine).instantiate_and_start(&mut store, module) else {
        panic!("instantiation must succeed");
    };
    (store, instance)
}

#[test]
fn br_table_equal_height_targets_read_their_branch_values() {
    // A `br_table` whose targets share a height copies nothing, so the branch
    // values have to already sit in the slots the targets read.
    let engine = build_wasm_engine();
    let module = compile(
        &engine,
        r#"
        (module
            (func $clobber (param i64 i64 i64))
            (func (export "probe") (param $i i32) (result i64 i64)
                (call $clobber (i64.const -1) (i64.const -1) (i64.const -1))
                (block (result i64 i64)
                    (i32.const 7)
                    (i64.const 0x1111)
                    (i64.const 0x2222)
                    (br_table 0 1 0 (local.get $i)))))
        "#,
    );
    for index in 0..3 {
        let (mut store, instance) = instantiate(&engine, &module);
        let Ok(probe) = instance.get_typed_func::<i32, (i64, i64)>(&store, "probe") else {
            panic!("probe export must be typed as expected");
        };
        match probe.call(&mut store, index) {
            Ok((low, high)) => assert_eq!(
                (low, high),
                (0x1111, 0x2222),
                "br_table index {index} read its branch values from the wrong slots"
            ),
            Err(err) => panic!("br_table index {index} trapped: {err}"),
        }
    }
}

#[test]
fn if_with_params_keeps_operands_when_then_block_writes_a_local() {
    let engine = build_wasm_engine();
    let module = compile(
        &engine,
        r#"
        (module
            (func (export "probe") (param $a i32) (param $b i32) (result i32)
                (i32.add (local.get $a) (i32.const 1))
                (local.get $b)
                (if (param i32) (result i32)
                    (then
                        (local.set $a (i32.add (local.get $b) (i32.const 100))))))
            (func (export "probe_else") (param $a i32) (param $b i32) (result i32)
                (i32.add (local.get $a) (i32.const 1))
                (local.get $b)
                (if (param i32) (result i32)
                    (then
                        (local.set $a (i32.add (local.get $b) (i32.const 100))))
                    (else))))
        "#,
    );
    for name in ["probe", "probe_else"] {
        for (args, expected) in [((42_i32, 0_i32), 43_i32), ((7, 1), 8)] {
            let (mut store, instance) = instantiate(&engine, &module);
            let Ok(func) = instance.get_typed_func::<(i32, i32), i32>(&store, name) else {
                panic!("{name} export must be typed as expected");
            };
            match func.call(&mut store, args) {
                Ok(value) => assert_eq!(
                    value, expected,
                    "{name}{args:?} read a stale register link instead of the operand"
                ),
                Err(err) => panic!("{name}{args:?} trapped: {err}"),
            }
        }
    }
}

#[test]
fn loop_with_params_does_not_clobber_a_preceding_local_tee() {
    let engine = build_wasm_engine();
    let module = compile(
        &engine,
        r#"
        (module
            (func (export "probe") (param $x i64) (param $y i32) (result i64)
                (local $l i64)
                (local.tee $l (i64.add (local.get $x) (i64.const 1)))
                (local.get $y)
                (loop (param i32) (drop))))
        "#,
    );
    for (args, expected) in [((41_i64, 7_i32), 42_i64), ((9, 100), 10)] {
        let (mut store, instance) = instantiate(&engine, &module);
        let Ok(func) = instance.get_typed_func::<(i64, i32), i64>(&store, "probe") else {
            panic!("probe export must be typed as expected");
        };
        match func.call(&mut store, args) {
            Ok(value) => assert_eq!(
                value, expected,
                "loop params{args:?} overwrote the register holding the local.tee result"
            ),
            Err(err) => panic!("loop params{args:?} trapped: {err}"),
        }
    }
}

#[test]
fn resuming_a_tail_called_host_trap_writes_the_callers_result_slots() {
    // The host function is tail called, so a resumption must write its result
    // into the caller's caller slots, not into the frame it replaced.
    let engine = build_wasm_engine();
    let module = compile(
        &engine,
        r#"
        (module
            (import "env" "host_fn" (func $host (param i32) (result i32)))
            (func $wasm (param i32 i32) (result i32)
                (return_call $host (local.get 1)))
            (func (export "test") (param $a i32) (param $b i32) (param $c i32)
                (result i32 i32 i32 i32)
                (local.get $a)
                (local.get $b)
                (local.get $c)
                (call $wasm (i32.const 10) (i32.const 20))))
        "#,
    );
    let mut store = funded_store(&engine);
    let mut linker = Linker::new(&engine);
    let host = wasmi::Func::wrap(&mut store, |_pending: i32| -> Result<i32, WasmiError> {
        Err(WasmiError::i32_exit(100))
    });
    if linker.define("env", "host_fn", host).is_err() {
        panic!("host function must be definable");
    }
    let Ok(instance) = linker.instantiate_and_start(&mut store, &module) else {
        panic!("instantiation must succeed");
    };
    let Ok(test) = instance.get_typed_func::<(i32, i32, i32), (i32, i32, i32, i32)>(&store, "test")
    else {
        panic!("test export must be typed as expected");
    };
    let Ok(invocation) = test.call_resumable(&mut store, (1, 2, 3)) else {
        panic!("call must start");
    };
    let TypedResumableCall::HostTrap(trap) = invocation else {
        panic!("expected a resumable host trap, got another resumable state");
    };
    match trap.resume(&mut store, &[Val::I32(42)]) {
        Ok(TypedResumableCall::Finished(results)) => assert_eq!(
            results,
            (1, 2, 3, 42),
            "the resumption wrote the host result into the wrong slots"
        ),
        Ok(_) => panic!("resumption must finish the call"),
        Err(err) => panic!("resumption failed: {err}"),
    }
}

#[test]
fn fuel_metering_is_byte_and_fuel_deterministic_across_runs() {
    let engine = build_wasm_engine();
    let module = compile(
        &engine,
        r#"
        (module
            (func (export "probe") (param $n i64) (result i64)
                (local $acc i64)
                (local $i i64)
                (block $done
                    (loop $again
                        (br_if $done (i64.ge_u (local.get $i) (local.get $n)))
                        (local.set $acc (i64.add (local.get $acc) (local.get $i)))
                        (local.set $i (i64.add (local.get $i) (i64.const 1)))
                        (br $again)))
                (local.get $acc)))
        "#,
    );

    // The first call on a fresh `Engine` costs a one-off amount more than later
    // calls on the same engine (measured here: 266 fuel for this body; 245 for a
    // simpler one). `WasmWorker` builds an engine per operation, so every call
    // pays it once and the charge stays equal across nodes; this test warms the
    // engine up so the comparison is between steady-state metering, then runs
    // three independent stores.
    let _ = call_once(&engine, &module, 8);

    let mut observed = None;
    for _ in 0..3 {
        let sample = (
            call_once(&engine, &module, 64),
            fuel_used(&engine, &module, 64),
        );
        match observed {
            None => observed = Some(sample),
            Some(first) => assert_eq!(
                sample, first,
                "identical input must return identical bytes and consume identical fuel"
            ),
        }
    }
}

fn call_once(engine: &Engine, module: &Module, n: i64) -> i64 {
    let (mut store, instance) = instantiate(engine, module);
    let Ok(probe) = instance.get_typed_func::<i64, i64>(&store, "probe") else {
        panic!("probe export must be typed as expected");
    };
    match probe.call(&mut store, n) {
        Ok(value) => value,
        Err(err) => panic!("probe must not trap: {err}"),
    }
}

fn fuel_used(engine: &Engine, module: &Module, n: i64) -> u64 {
    let (mut store, instance) = instantiate(engine, module);
    let Ok(probe) = instance.get_typed_func::<i64, i64>(&store, "probe") else {
        panic!("probe export must be typed as expected");
    };
    let before = store.get_fuel().unwrap_or(0);
    if probe.call(&mut store, n).is_err() {
        panic!("probe must not trap");
    }
    before - store.get_fuel().unwrap_or(0)
}

#[test]
fn floating_point_stays_refused_by_the_engine_configuration() {
    let engine = build_wasm_engine();
    let Ok(bytes) = wat::parse_str(
        r#"
        (module
            (func (export "probe") (result f64)
                (f64.const 1.5)))
        "#,
    ) else {
        panic!("test module must assemble");
    };
    assert!(
        Module::new(&engine, &bytes).is_err(),
        "the worker engine must keep floating point disabled"
    );
}
