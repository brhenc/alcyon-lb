//! NASA JPL "Power of 10" Safety Contracts and Assertions
//!
//! Rule 2: Loop bounds checked statically or dynamically bounded.
//! Rule 5: Assertion density with verifiable side-effect free contracts.

use std::sync::atomic::{AtomicU64, Ordering};

/// Global telemetry counter for evaluated and failed assertions.
pub static ASSERTIONS_EVALUATED: AtomicU64 = AtomicU64::new(0);
pub static ASSERTIONS_FAILED: AtomicU64 = AtomicU64::new(0);

/// Safety Contract helper for checking invariants without panicking on production paths.
pub struct SafetyContract;

impl SafetyContract {
    #[inline(always)]
    pub fn record_check(passed: bool) {
        ASSERTIONS_EVALUATED.fetch_add(1, Ordering::Relaxed);
        if !passed {
            ASSERTIONS_FAILED.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Evaluates an assertion according to NASA JPL Rule 5.
/// In debug/test builds, this will assert. In release builds, it records failure to metrics.
#[macro_export]
macro_rules! ibex_assert {
    ($cond:expr) => {
        $crate::ibex_assert!($cond, stringify!($cond))
    };
    ($cond:expr, $msg:expr) => {
        let cond_val = $cond;
        $crate::jpl::SafetyContract::record_check(cond_val);
        if !cond_val {
            ::tracing::error!(
                target: "ibex::safety",
                condition = $msg,
                file = file!(),
                line = line!(),
                "NASA JPL Safety assertion violated"
            );
            #[cfg(any(debug_assertions, test))]
            {
                panic!("Assertion failed: {} ({}:{})", $msg, file!(), line!());
            }
        }
    };
}

/// Fallible ensure macro that returns an `IbexResult::Err(IbexError::AssertionFailed)`
/// if the expression evaluates to false.
#[macro_export]
macro_rules! ibex_ensure {
    ($cond:expr) => {
        $crate::ibex_ensure!($cond, stringify!($cond))
    };
    ($cond:expr, $msg:expr) => {
        let cond_val = $cond;
        $crate::jpl::SafetyContract::record_check(cond_val);
        if !cond_val {
            return Err($crate::error::IbexError::AssertionFailed {
                condition: $msg,
                location: concat!(file!(), ":", line!()),
            });
        }
    };
}

/// Bounded loop execution enforcing NASA JPL Rule 2 (fixed loop bounds).
#[macro_export]
macro_rules! bounded_loop {
    ($max_iterations:expr, $body:expr) => {{
        let mut __iter_count: usize = 0;
        let __max: usize = $max_iterations;
        let mut __completed = false;
        while __iter_count < __max {
            __iter_count += 1;
            if $body {
                __completed = true;
                break;
            }
        }
        if !__completed && __iter_count >= __max {
            Err($crate::error::IbexError::LoopBoundExceeded {
                max_iterations: __max,
            })
        } else {
            Ok(__iter_count)
        }
    }};
}
