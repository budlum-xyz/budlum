use crate::execution::coordinator::conformance::{
    calibrate_bgu_schedule, run_budzero_conformance, run_evm_conformance, run_move_conformance,
    run_svm_conformance, run_wasm_conformance, CalibratedBguSchedule, TARGET_MAX_NS_PER_BGU_P95,
};
use budlum_uel_abi::EeId;

#[test]
fn uel_conformance_evm() {
    let r1 = run_evm_conformance().expect("evm conformance");
    let r2 = run_evm_conformance().expect("evm conformance repeat");
    assert_eq!(r1.ee, EeId::EVM);
    assert!(r1.passed_vectors >= 4);
    assert!(r1.documented_limit_refusals >= 1);
    assert_eq!(r1.final_execution_root, r2.final_execution_root);
}

#[test]
fn uel_conformance_wasm() {
    let r1 = run_wasm_conformance().expect("wasm conformance");
    let r2 = run_wasm_conformance().expect("wasm conformance repeat");
    assert_eq!(r1.ee, EeId::WASM);
    assert!(r1.passed_vectors >= 3);
    assert_eq!(r1.documented_limit_refusals, 2);
    assert_eq!(r1.final_execution_root, r2.final_execution_root);
}

#[test]
fn uel_conformance_svm() {
    let r1 = run_svm_conformance().expect("svm conformance");
    let r2 = run_svm_conformance().expect("svm conformance repeat");
    assert_eq!(r1.ee, EeId::SVM);
    assert!(r1.passed_vectors >= 3);
    assert_eq!(r1.documented_limit_refusals, 2);
    assert_eq!(r1.final_execution_root, r2.final_execution_root);
}

#[test]
fn uel_conformance_move() {
    let r1 = run_move_conformance().expect("move conformance");
    let r2 = run_move_conformance().expect("move conformance repeat");
    assert_eq!(r1.ee, EeId::MOVE);
    assert!(r1.passed_vectors >= 2);
    assert_eq!(r1.documented_limit_refusals, 2);
    assert_eq!(r1.final_execution_root, r2.final_execution_root);
}

#[test]
fn uel_conformance_budzero() {
    let r1 = run_budzero_conformance().expect("budzero conformance");
    let r2 = run_budzero_conformance().expect("budzero conformance repeat");
    assert_eq!(r1.ee, EeId::BUDZERO);
    assert!(r1.passed_vectors >= 2);
    assert_eq!(r1.final_execution_root, r2.final_execution_root);
}

#[test]
fn uel_gas_calibration_bound() {
    let (p95_ns, sched) = calibrate_bgu_schedule(25).expect("calibrate");
    // Effective ns per calibrated BGU (`p95_ns / sched.evm_gas_to_bgu`) never exceeds 16 ns!
    let effective_ns_per_bgu = p95_ns / sched.evm_gas_to_bgu.max(1);
    assert!(
        effective_ns_per_bgu <= TARGET_MAX_NS_PER_BGU_P95,
        "calibrated effective ns/BGU ({effective_ns_per_bgu}) exceeded 16 ns target"
    );
    assert_eq!(CalibratedBguSchedule::recalibrate_factor(1, 16), 1);
    assert_eq!(CalibratedBguSchedule::recalibrate_factor(1, 17), 2);
    assert_eq!(CalibratedBguSchedule::recalibrate_factor(100, 32), 200);
}
