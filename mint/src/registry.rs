use std::sync::Arc;

use serde::Serialize;
use tokio::sync::Mutex;
use zns_state::{Name, State, StateError};

/// Table counters for the control plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RegistryStats {
    pub names: u64,
    pub pending_challenges: u64,
}

/// Async handle to the registry SQLite store.
#[derive(Clone)]
pub struct Registry {
    inner: Arc<Mutex<State>>,
}

impl Registry {
    pub fn new(state: State) -> Self {
        Self {
            inner: Arc::new(Mutex::new(state)),
        }
    }

    pub async fn lock(&self) -> tokio::sync::MutexGuard<'_, State> {
        self.inner.lock().await
    }

    pub async fn lookup(&self, name: &str) -> Result<Option<Name>, StateError> {
        let st = self.inner.lock().await;
        st.get_record(name)
    }

    pub async fn stats(&self) -> Result<RegistryStats, StateError> {
        let st = self.inner.lock().await;
        let (names, pending_challenges) = st.table_counts()?;
        Ok(RegistryStats {
            names,
            pending_challenges,
        })
    }
}