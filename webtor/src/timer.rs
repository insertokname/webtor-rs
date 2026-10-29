//! Timers that keep time while the page is in the background.
//!
//! Browsers throttle the timers of hidden pages: at most once a second, and
//! Chromium, after five minutes hidden, runs chained timers only once a
//! minute. Keepalives (the SMUX NOP every 10 s, the bridge's silence checked
//! every 5 s) must not slow down with them: a dead bridge would go unnoticed
//! for over a minute. The embedding page can hand webtor timer functions
//! that are not throttled that way (a dedicated worker's timers, see
//! `setTimerFunctions` in webtor-wasm); without them, and outside the
//! browser, this is an ordinary sleep.

use std::time::Duration;

#[cfg(target_arch = "wasm32")]
mod wasm {
    use futures::channel::oneshot;
    use std::cell::RefCell;
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use wasm_bindgen::prelude::*;
    use wasm_bindgen::JsCast;

    struct TimerFunctions {
        set: js_sys::Function,
        clear: js_sys::Function,
    }

    thread_local! {
        static FUNCTIONS: RefCell<Option<TimerFunctions>> = const { RefCell::new(None) };
    }

    /// `set(callback, ms)` returns a handle, `clear(handle)` cancels it.
    pub fn set_functions(set: js_sys::Function, clear: js_sys::Function) {
        FUNCTIONS.with(|f| *f.borrow_mut() = Some(TimerFunctions { set, clear }));
    }

    /// A sleep on the page's timer functions; cleared when dropped early.
    pub struct UnthrottledSleep {
        rx: oneshot::Receiver<()>,
        handle: Option<JsValue>,
        _callback: Closure<dyn FnMut()>,
    }

    impl UnthrottledSleep {
        /// None when the page gave no timer functions or they failed.
        pub fn new(ms: u32) -> Option<Self> {
            let (tx, rx) = oneshot::channel();
            let mut tx = Some(tx);
            let callback = Closure::<dyn FnMut()>::new(move || {
                if let Some(tx) = tx.take() {
                    let _ = tx.send(());
                }
            });
            let handle = FUNCTIONS.with(|f| {
                let f = f.borrow();
                let f = f.as_ref()?;
                f.set
                    .call2(
                        &JsValue::NULL,
                        callback.as_ref().unchecked_ref(),
                        &JsValue::from(ms),
                    )
                    .ok()
            })?;
            Some(Self {
                rx,
                handle: Some(handle),
                _callback: callback,
            })
        }
    }

    impl Future for UnthrottledSleep {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            use futures::FutureExt;
            match self.rx.poll_unpin(cx) {
                Poll::Ready(_) => {
                    self.handle = None;
                    Poll::Ready(())
                }
                Poll::Pending => Poll::Pending,
            }
        }
    }

    impl Drop for UnthrottledSleep {
        fn drop(&mut self) {
            if let Some(handle) = self.handle.take() {
                FUNCTIONS.with(|f| {
                    if let Some(f) = f.borrow().as_ref() {
                        let _ = f.clear.call1(&JsValue::NULL, &handle);
                    }
                });
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub use wasm::set_functions;

/// Sleeps for `duration` on the page's unthrottled timers when it gave
/// some, otherwise as `crate::retry::sleep`.
pub async fn unthrottled_sleep(duration: Duration) {
    #[cfg(target_arch = "wasm32")]
    {
        let ms = duration.as_millis().min(u32::MAX as u128) as u32;
        if let Some(sleep) = wasm::UnthrottledSleep::new(ms) {
            sleep.await;
            return;
        }
    }
    crate::retry::sleep(duration).await;
}
