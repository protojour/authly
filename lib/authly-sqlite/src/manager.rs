use std::{
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicUsize, Ordering},
};

use deadpool::managed::{Metrics, RecycleError, RecycleResult};
use rusqlite::Connection;

use crate::Storage;

pub struct ConnectionWrapper {
    conn: Option<Connection>,
}

impl Deref for ConnectionWrapper {
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        self.conn.as_ref().unwrap()
    }
}

impl DerefMut for ConnectionWrapper {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.conn.as_mut().unwrap()
    }
}

pub struct SqlitePoolManager {
    storage: Storage,
    recycle_count: AtomicUsize,
}

impl SqlitePoolManager {
    pub fn new(storage: Storage) -> Self {
        Self {
            storage,
            recycle_count: AtomicUsize::new(0),
        }
    }
}

impl deadpool::managed::Manager for SqlitePoolManager {
    type Type = ConnectionWrapper;
    type Error = rusqlite::Error;

    async fn create(&self) -> Result<Self::Type, Self::Error> {
        let conn = match &self.storage {
            Storage::File(path) => {
                let path = path.clone();
                rusqlite::Connection::open(path)?
            }
            Storage::Memory => rusqlite::Connection::open_in_memory()?,
        };

        Ok(ConnectionWrapper { conn: Some(conn) })
    }

    async fn recycle(
        &self,
        wrapper_mut: &mut Self::Type,
        _: &Metrics,
    ) -> RecycleResult<Self::Error> {
        let recycle_count = self.recycle_count.fetch_add(1, Ordering::Relaxed);

        let conn = wrapper_mut.conn.take().unwrap();

        let (n, conn): (usize, Connection) = tokio::task::spawn_blocking(move || {
            match conn.query_row("SELECT $1", [recycle_count], |row| row.get(0)) {
                Ok(n) => Ok((n, conn)),
                Err(e) => Err(RecycleError::message(format!("{}", e))),
            }
        })
        .await
        .map_err(|_| RecycleError::message("blocking when recycling"))??;

        if n == recycle_count {
            wrapper_mut.conn = Some(conn);
            Ok(())
        } else {
            Err(RecycleError::message("Recycle count mismatch"))
        }
    }
}
