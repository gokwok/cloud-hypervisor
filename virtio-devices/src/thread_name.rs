// Copyright © 2025
//
// SPDX-License-Identifier: Apache-2.0
//

//! Logical thread names for threads whose kernel `comm` changes after spawn.
//!
//! `std::thread::Builder::name()` is applied once at spawn time and the Rust
//! side name cannot be updated afterwards, while `pthread_setname_np` only
//! updates the kernel `comm`. A thread spawned placeholder-named and renamed
//! later, as a prepared worker is, would otherwise keep showing the placeholder
//! in the Rust-side consumers such as the logging `{thread}` token and the
//! default panic hook.
//!
//! Callers that rename a thread at run time also record the new name here, and
//! those consumers prefer the recorded name over `thread::current().name()`.

use std::cell::RefCell;

thread_local! {
    static LOGICAL_NAME: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Record the logical name of the current thread.
///
/// Call this together with (or instead of) `pthread_setname_np` so that the
/// Rust-side consumers agree with the kernel `comm`.
pub fn set_logical_thread_name(name: impl Into<String>) {
    LOGICAL_NAME.with(|slot| *slot.borrow_mut() = Some(name.into()));
}

/// The logical name recorded for the current thread, if any.
pub fn logical_thread_name() -> Option<String> {
    LOGICAL_NAME.with(|slot| slot.borrow().clone())
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;

    #[test]
    fn unset_by_default() {
        let handle = thread::spawn(logical_thread_name);
        assert_eq!(handle.join().unwrap(), None);
    }

    #[test]
    fn set_name_is_per_thread() {
        set_logical_thread_name("main-thread");
        assert_eq!(logical_thread_name().as_deref(), Some("main-thread"));

        let other = thread::spawn(|| {
            assert_eq!(logical_thread_name(), None);
            set_logical_thread_name("worker");
            logical_thread_name()
        });
        assert_eq!(other.join().unwrap().as_deref(), Some("worker"));

        // The main thread keeps its own value.
        assert_eq!(logical_thread_name().as_deref(), Some("main-thread"));
    }

    #[test]
    fn set_name_overrides() {
        set_logical_thread_name("first");
        set_logical_thread_name("second");
        assert_eq!(logical_thread_name().as_deref(), Some("second"));
    }
}
