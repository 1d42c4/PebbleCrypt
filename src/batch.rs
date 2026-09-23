//! Batch orchestration, kept independent of the window so races can be tested.
use crate::crypto::{self, Job, Mode};
use age::secrecy::SecretString;
use std::{
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
};

#[derive(Debug, Default)]
pub struct Report {
    pub outputs: Vec<PathBuf>,
    pub error: Option<String>,
    pub cancelled: bool,
}

pub struct Progress {
    pub index: usize,
    pub count: usize,
    pub done: u64,
    pub total: u64,
    pub preparing: bool,
}

pub fn run(
    jobs: &[Job],
    mode: Mode,
    password: SecretString,
    cancel: &AtomicBool,
    notify: &mut impl FnMut(Progress),
) -> Report {
    run_with(jobs, cancel, notify, &mut |job, progress| {
        crypto::transform(job, mode, password.clone(), cancel, &mut |done, total| {
            progress(done, total)
        })
    })
}

fn run_with(
    jobs: &[Job],
    cancel: &AtomicBool,
    notify: &mut impl FnMut(Progress),
    process: &mut impl FnMut(&Job, &mut dyn FnMut(u64, u64)) -> Result<(), String>,
) -> Report {
    let mut report = Report::default();
    for (index, job) in jobs.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        notify(Progress {
            index,
            count: jobs.len(),
            done: 0,
            total: 0,
            preparing: true,
        });
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            process(job, &mut |done, total| notify(Progress { index, count: jobs.len(), done, total, preparing: false }))
        })).unwrap_or_else(|_| Err("An unexpected error stopped this file. Check the output folder for any completed result.".into()));
        match result {
            Ok(()) => report.outputs.push(job.output.clone()),
            Err(message) => {
                // Cancellation must not conceal a disk error, failed cleanup, or a panic.
                if message != "Cancelled." || !cancel.load(Ordering::Relaxed) {
                    report.error = Some(format!(
                        "{}: {message}",
                        job.input.file_name().unwrap_or_default().to_string_lossy()
                    ));
                }
                break;
            }
        }
    }
    report.cancelled = report.error.is_none()
        && cancel.load(Ordering::Relaxed)
        && report.outputs.len() < jobs.len();
    report
}

#[cfg(test)]
#[path = "batch_tests.rs"]
mod tests;
