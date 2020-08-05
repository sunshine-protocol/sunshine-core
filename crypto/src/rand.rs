use async_std::task;
use rand::{thread_rng, Rng};

/// Async random number generator.
pub async fn random<T: Default + AsMut<[u8]> + Send + 'static>() -> T {
    task::spawn_blocking(|| {
        let mut buf = T::default();
        thread_rng().fill(buf.as_mut());
        buf
    })
    .await
}
