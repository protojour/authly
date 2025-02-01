use std::{
    borrow::Cow,
    ops::{Deref, DerefMut},
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

use deadpool::managed::{Metrics, Object, Pool, PoolConfig, RecycleError, RecycleResult};
use hiqlite::Params;
use rusqlite::Connection;

use crate::{
    sqlite::{sqlite_execute, sqlite_query_map, sqlite_query_raw, sqlite_txn, RusqliteRowOwned},
    Db, DbError,
};

#[derive(Clone)]
pub enum Storage {
    File(PathBuf),
    Memory,
}

#[derive(Clone)]
pub struct SqlitePool {
    pool: Pool<SimpleManager>,
}

impl SqlitePool {
    pub fn new(storage: Storage, pool_size: usize) -> Self {
        let pool = Pool::builder(SimpleManager::new(storage))
            .config(PoolConfig::new(pool_size))
            .build()
            .unwrap();

        Self { pool }
    }

    pub async fn get(&self) -> Result<Object<SimpleManager>, DbError> {
        self.pool.get().await.map_err(|_| DbError::Channel)
    }
}

impl Db for SqlitePool {
    type Row<'a> = RusqliteRowOwned;

    async fn query_raw(
        &self,
        stmt: Cow<'static, str>,
        params: Params,
    ) -> Result<Vec<Self::Row<'_>>, DbError> {
        let conn = self.get().await?;

        tokio::task::spawn_blocking(move || sqlite_query_raw(&conn, stmt, params))
            .await
            .map_err(|_| DbError::Channel)?
    }

    async fn query_map<T>(&self, stmt: Cow<'static, str>, params: Params) -> Result<Vec<T>, DbError>
    where
        T: crate::FromRow + Send + 'static,
    {
        let conn = self.get().await?;

        tokio::task::spawn_blocking(move || sqlite_query_map(&conn, stmt, params))
            .await
            .map_err(|_| DbError::Channel)?
    }

    async fn execute(&self, stmt: Cow<'static, str>, params: Params) -> Result<usize, DbError> {
        let conn = self.get().await?;

        tokio::task::spawn_blocking(move || sqlite_execute(&conn, stmt, params))
            .await
            .map_err(|_| DbError::Channel)?
    }

    async fn transact(
        &self,
        sql: Vec<(Cow<'static, str>, Params)>,
    ) -> Result<Vec<Result<usize, DbError>>, DbError> {
        let mut conn = self.get().await?;

        tokio::task::spawn_blocking(move || sqlite_txn(&mut conn, sql))
            .await
            .map_err(|_| DbError::Channel)?
    }
}

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

pub struct SimpleManager {
    storage: Storage,
    recycle_count: AtomicUsize,
}

impl SimpleManager {
    pub fn new(storage: Storage) -> Self {
        Self {
            storage,
            recycle_count: AtomicUsize::new(0),
        }
    }
}

impl deadpool::managed::Manager for SimpleManager {
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
