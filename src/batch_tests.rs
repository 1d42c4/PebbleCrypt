use super::*;
fn jobs() -> Vec<Job> {
    (0..3)
        .map(|n| Job {
            input: format!("{n}.input").into(),
            output: format!("{n}.output").into(),
        })
        .collect()
}
#[test]
fn successful_batch_reports_all_outputs_in_order() {
    let j = jobs();
    let r = run_with(&j, &AtomicBool::new(false), &mut |_| {}, &mut |_, _| Ok(()));
    assert_eq!(
        r.outputs,
        j.iter().map(|j| j.output.clone()).collect::<Vec<_>>()
    );
    assert!(!r.cancelled);
    assert!(r.error.is_none());
}
#[test]
fn empty_batch_is_safe() {
    let r = run_with(
        &[],
        &AtomicBool::new(false),
        &mut |_| panic!("no progress expected"),
        &mut |_, _| panic!("no job expected"),
    );
    assert!(r.outputs.is_empty() && r.error.is_none() && !r.cancelled);
}
#[test]
fn cancellation_before_first_file_runs_no_jobs() {
    let r = run_with(&jobs(), &AtomicBool::new(true), &mut |_| {}, &mut |_, _| {
        panic!("should not run")
    });
    assert!(r.cancelled && r.outputs.is_empty());
}
#[test]
fn cancellation_between_files_preserves_completed_result() {
    let cancel = AtomicBool::new(false);
    let j = jobs();
    let r = run_with(&j, &cancel, &mut |_| {}, &mut |_, _| {
        cancel.store(true, Ordering::Relaxed);
        Ok(())
    });
    assert_eq!(r.outputs, vec![j[0].output.clone()]);
    assert!(r.cancelled);
}
#[test]
fn cancellation_on_final_commit_reports_success() {
    let cancel = AtomicBool::new(false);
    let j = jobs();
    let mut n = 0;
    let r = run_with(&j, &cancel, &mut |_| {}, &mut |_, _| {
        n += 1;
        if n == 3 {
            cancel.store(true, Ordering::Relaxed);
        }
        Ok(())
    });
    assert_eq!(r.outputs.len(), 3);
    assert!(!r.cancelled);
}
#[test]
fn error_stops_batch_and_keeps_prior_files() {
    let mut n = 0;
    let r = run_with(
        &jobs(),
        &AtomicBool::new(false),
        &mut |_| {},
        &mut |_, _| {
            n += 1;
            if n == 2 {
                Err("disk full".into())
            } else {
                Ok(())
            }
        },
    );
    assert_eq!(n, 2);
    assert_eq!(r.outputs.len(), 1);
    assert!(r.error.unwrap().contains("1.input: disk full"));
}
#[test]
fn panic_stops_batch_and_keeps_prior_files() {
    let mut n = 0;
    let r = run_with(
        &jobs(),
        &AtomicBool::new(false),
        &mut |_| {},
        &mut |_, _| {
            n += 1;
            if n == 2 {
                panic!("injected panic");
            }
            Ok(())
        },
    );
    assert_eq!(n, 2);
    assert_eq!(r.outputs.len(), 1);
    assert!(r.error.unwrap().contains("unexpected error"));
}
#[test]
fn cancellation_never_masks_cleanup_failure() {
    let cancel = AtomicBool::new(false);
    let r = run_with(&jobs(), &cancel, &mut |_| {}, &mut |_, _| {
        cancel.store(true, Ordering::Relaxed);
        Err("Cancelled. Could not remove temporary plaintext".into())
    });
    assert!(r.error.unwrap().contains("plaintext"));
    assert!(!r.cancelled);
}
#[test]
fn cancellation_never_masks_disk_failure() {
    let cancel = AtomicBool::new(false);
    let r = run_with(&jobs(), &cancel, &mut |_| {}, &mut |_, _| {
        cancel.store(true, Ordering::Relaxed);
        Err("disk full".into())
    });
    assert!(r.error.unwrap().contains("disk full"));
    assert!(!r.cancelled);
}
#[test]
fn clean_cancellation_is_not_reported_as_error() {
    let cancel = AtomicBool::new(false);
    let r = run_with(&jobs(), &cancel, &mut |_| {}, &mut |_, _| {
        cancel.store(true, Ordering::Relaxed);
        Err("Cancelled.".into())
    });
    assert!(r.cancelled);
    assert!(r.error.is_none());
}
#[test]
fn cancellation_message_without_signal_is_an_error() {
    let r = run_with(
        &jobs(),
        &AtomicBool::new(false),
        &mut |_| {},
        &mut |_, _| Err("Cancelled.".into()),
    );
    assert!(r.error.is_some());
    assert!(!r.cancelled);
}
#[test]
fn progress_identifies_file_and_stage() {
    let mut events = vec![];
    run_with(
        &jobs(),
        &AtomicBool::new(false),
        &mut |p| events.push((p.index, p.count, p.done, p.total, p.preparing)),
        &mut |_, p| {
            p(10, 20);
            p(20, 20);
            Ok(())
        },
    );
    assert_eq!(events.len(), 9);
    for i in 0..3 {
        assert_eq!(events[i * 3], (i, 3, 0, 0, true));
        assert_eq!(events[i * 3 + 1], (i, 3, 10, 20, false));
    }
}
