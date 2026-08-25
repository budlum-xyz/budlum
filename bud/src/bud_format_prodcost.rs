//! B.U.D. 2.0 - THE PRODUCTION COST TABLE (ideas 2.0, I3 - closing "the
//! production cost was never measured").
//!
//! The price function input of the I3 production market: the UNIT cost of each
//! pipeline step. The numbers are derived from sandbox measurements on
//! 2026-08-16 (zstd/xz/ffmpeg timings and published benchmarks); `measure()`
//! can take a live measurement.
//! The economics: the validator's production cost sits on the CPU side, while
//! the user sees a SINGLE PRICE (flat_price).

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const PRODCOST_MAGIC: [u8; 8] = *b"\xB5COST\0\0\0";

/// The cost model of a pipeline step: MB/s (of output or input, depending on
/// the step).
#[derive(Debug, Clone, Copy)]
pub struct StepCost {
    pub step: &'static str,
    pub mb_per_s: f64,       // the processing rate (measured or published)
    pub cpu_sec_per_tb: f64, // computed: 1_048_576 MB / mb_per_s
}

pub const STEPS: &[StepCost] = &[
    StepCost {
        step: "detect",
        mb_per_s: 12_000.0,
        cpu_sec_per_tb: 87.4,
    },
    StepCost {
        step: "columnar-json",
        mb_per_s: 420.0,
        cpu_sec_per_tb: 2496.6,
    },
    StepCost {
        step: "logfield",
        mb_per_s: 380.0,
        cpu_sec_per_tb: 2759.4,
    },
    StepCost {
        step: "structural-split",
        mb_per_s: 2_400.0,
        cpu_sec_per_tb: 436.9,
    },
    StepCost {
        step: "fastcdc",
        mb_per_s: 3_500.0,
        cpu_sec_per_tb: 299.6,
    },
    StepCost {
        step: "zstd-3",
        mb_per_s: 640.0,
        cpu_sec_per_tb: 1638.4,
    },
    StepCost {
        step: "zstd-19",
        mb_per_s: 90.0,
        cpu_sec_per_tb: 11650.8,
    },
    StepCost {
        step: "xz-9e",
        mb_per_s: 22.0,
        cpu_sec_per_tb: 47662.5,
    },
    StepCost {
        step: "cauchy-erasure-enc",
        mb_per_s: 120.0,
        cpu_sec_per_tb: 8738.1,
    },
    StepCost {
        step: "cauchy-erasure-dec",
        mb_per_s: 260.0,
        cpu_sec_per_tb: 4032.9,
    },
    StepCost {
        step: "sha3-256",
        mb_per_s: 1_100.0,
        cpu_sec_per_tb: 953.3,
    },
    StepCost {
        step: "avif-lossy (media)",
        mb_per_s: 45.0,
        cpu_sec_per_tb: 23301.7,
    },
    StepCost {
        step: "jxl-lossless (media)",
        mb_per_s: 30.0,
        cpu_sec_per_tb: 34952.6,
    },
    StepCost {
        step: "flac (audio)",
        mb_per_s: 250.0,
        cpu_sec_per_tb: 4194.3,
    },
    StepCost {
        step: "av1 (video)",
        mb_per_s: 60.0,
        cpu_sec_per_tb: 17476.3,
    },
];

/// Find a step cost by its name.
pub fn step_cost(name: &str) -> Option<&'static StepCost> {
    STEPS.iter().find(|s| s.step == name)
}

/// The total CPU time of the pipeline (seconds per TB) - the price function
/// input.
pub fn pipeline_cpu_sec_per_tb(steps: &[&str]) -> f64 {
    steps
        .iter()
        .filter_map(|s| step_cost(s))
        .map(|s| s.cpu_sec_per_tb)
        .sum()
}

/// The dollar value of a CPU second (validator hardware amortisation, about
/// $0.00002 per CPU second).
pub const USD_PER_CPU_SEC: f64 = 0.00002;

/// The production cost of the pipeline: dollars per TB.
pub fn pipeline_production_usd_per_tb(steps: &[&str]) -> f64 {
    pipeline_cpu_sec_per_tb(steps) * USD_PER_CPU_SEC
}

/// The evidence digest (deterministic).
pub fn cost_digest() -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(PRODCOST_MAGIC);
    for s in STEPS {
        h.update(s.step.as_bytes());
        h.update(s.mb_per_s.to_le_bytes());
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_step_cost_is_positive_and_plausible() {
        for s in STEPS {
            assert!(s.mb_per_s > 0.0, "{} has a rate of 0", s.step);
            assert!(s.cpu_sec_per_tb > 0.0);
            // 1 TB = 1_048_576 MB, so cpu_sec = MB / mb_per_s
            let expected = 1_048_576.0 / s.mb_per_s;
            assert!(
                (s.cpu_sec_per_tb - expected).abs() < 1.0,
                "{} is inconsistent",
                s.step
            );
        }
    }

    #[test]
    fn an_easy_pipeline_is_cheap_and_a_heavy_one_is_expensive() {
        let light = pipeline_production_usd_per_tb(&["detect", "structural-split", "zstd-3"]);
        let heavy = pipeline_production_usd_per_tb(&[
            "detect",
            "columnar-json",
            "zstd-19",
            "cauchy-erasure-enc",
            "sha3-256",
        ]);
        assert!(heavy > light);
        assert!(light > 0.0);
    }

    #[test]
    fn an_unknown_step_contributes_zero() {
        assert!(step_cost("no-such-step").is_none());
        assert_eq!(pipeline_cpu_sec_per_tb(&["none"]), 0.0);
    }

    #[test]
    fn the_cost_digest_is_deterministic() {
        assert_eq!(cost_digest(), cost_digest());
    }
}
