use std::{
    borrow::Cow,
    fmt::Debug,
    ops::{Deref, DerefMut},
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

use deadpool::managed::{Metrics, Object, Pool, PoolConfig, RecycleError, RecycleResult};
use hiqlite::{Param, Params};
use rusqlite::{types::Value, Connection};

use crate::{
    sqlite::{rusqlite_params, RusqliteRowBorrowed},
    Db, DbError, FromRow, TryFromRow,
};

#[derive(Clone)]
pub enum Storage {
    File(PathBuf),
    Memory,
}

#[derive(Clone)]
pub struct SqlitePool {
    pool: Pool<SqlitePoolManager>,
}

impl SqlitePool {
    pub fn new(storage: Storage, pool_size: usize) -> Self {
        let pool = Pool::builder(SqlitePoolManager::new(storage))
            .config(PoolConfig::new(pool_size))
            .build()
            .unwrap();

        Self { pool }
    }

    pub async fn get(&self) -> Result<Object<SqlitePoolManager>, DbError> {
        self.pool
            .get()
            .await
            .map_err(|err| DbError::Pool(format!("{err:?}")))
    }
}

impl Db for SqlitePool {
    async fn query_map<T>(&self, stmt: Cow<'static, str>, params: Params) -> Result<Vec<T>, DbError>
    where
        T: FromRow + Send + 'static,
    {
        let conn = self.get().await?;

        tokio::task::spawn_blocking(move || {
            let mut stmt = conn.prepare_cached(&stmt)?;
            let mut rows = stmt.query(rusqlite_params(params))?;

            let mut output = vec![];

            while let Some(row) = rows.next()? {
                output.push(T::from_row(&mut RusqliteRowBorrowed { row }));
            }

            Ok(output)
        })
        .await?
    }

    async fn query_map_opt<T>(
        &self,
        stmt: Cow<'static, str>,
        params: Params,
    ) -> Result<Option<T>, DbError>
    where
        T: FromRow + Send + 'static,
    {
        let conn = self.get().await?;

        tokio::task::spawn_blocking(move || {
            let mut stmt = conn.prepare_cached(&stmt)?;
            let mut rows = stmt.query(rusqlite_params(params))?;

            let mut output = None;

            if let Some(row) = rows.next()? {
                output = Some(T::from_row(&mut RusqliteRowBorrowed { row }));

                if rows.next()?.is_some() {
                    return Err(DbError::TooManyRows);
                }
            }

            Ok(output)
        })
        .await?
    }

    async fn query_try_map_opt<T>(
        &self,
        stmt: Cow<'static, str>,
        params: Params,
    ) -> Result<Option<Result<T, T::Error>>, DbError>
    where
        T: TryFromRow + Send + 'static,
    {
        let conn = self.get().await?;

        tokio::task::spawn_blocking(move || {
            let mut stmt = conn.prepare_cached(&stmt)?;
            let mut rows = stmt.query(rusqlite_params(params))?;

            let mut output = None;

            if let Some(row) = rows.next()? {
                output = Some(T::try_from_row(&mut RusqliteRowBorrowed { row }));

                if rows.next()?.is_some() {
                    return Err(DbError::TooManyRows);
                }
            }

            Ok(output)
        })
        .await?
    }

    async fn query_filter_map<T>(
        &self,
        stmt: Cow<'static, str>,
        params: Params,
    ) -> Result<Vec<T>, DbError>
    where
        T: TryFromRow + Send + 'static,
        <T as TryFromRow>::Error: Debug,
    {
        let conn = self.get().await?;

        tokio::task::spawn_blocking(move || {
            let mut stmt = conn.prepare_cached(&stmt)?;
            let mut rows = stmt.query(rusqlite_params(params))?;

            let mut output = vec![];

            while let Some(row) = rows.next()? {
                match T::try_from_row(&mut RusqliteRowBorrowed { row }) {
                    Ok(value) => output.push(value),
                    Err(err) => {
                        tracing::error!(?err, "row error");
                    }
                }
            }

            Ok(output)
        })
        .await?
    }

    async fn execute(&self, stmt: Cow<'static, str>, params: Params) -> Result<usize, DbError> {
        let conn = self.get().await?;

        tokio::task::spawn_blocking(move || {
            Ok(rusqlite::Connection::execute(
                &conn,
                &stmt,
                rusqlite_params(params),
            )?)
        })
        .await?
    }

    async fn execute_map<T>(
        &self,
        sql: Cow<'static, str>,
        params: Params,
    ) -> Result<Vec<Result<T, DbError>>, DbError>
    where
        T: FromRow + Send + 'static,
    {
        let conn = self.get().await?;

        tokio::task::spawn_blocking(move || {
            let mut stmt = conn.prepare_cached(&sql)?;
            let mut rows = stmt.query(rusqlite_params(params))?;

            let mut output = vec![];

            while let Some(row) = rows.next()? {
                output.push(Ok(T::from_row(&mut RusqliteRowBorrowed { row })));
            }

            Ok(output)
        })
        .await?
    }

    async fn transact(
        &self,
        sql: Vec<(Cow<'static, str>, Params)>,
    ) -> Result<Vec<Result<usize, DbError>>, DbError> {
        let mut conn = self.get().await?;

        tokio::task::spawn_blocking(move || {
            let txn = conn.transaction()?;

            let mut output = vec![];

            let mut executed_sql: Vec<Cow<'static, str>> = Vec::with_capacity(sql.len());
            let mut executed_rows: Vec<Vec<Value>> = Vec::with_capacity(sql.len());

            for (sql, params) in sql {
                let mut stmt = txn.prepare_cached(&sql).map_err(DbError::Rusqlite)?;
                for (idx, param) in params.into_iter().enumerate() {
                    let rparam = match param {
                        Param::Null => Value::Null,
                        Param::Integer(i) => Value::Integer(i),
                        Param::Real(r) => Value::Real(r),
                        Param::Text(t) => Value::Text(t),
                        Param::Blob(b) => Value::Blob(b),
                        Param::StmtOutputIndexed(stmt_idx, col_idx) => {
                            executed_rows[stmt_idx][col_idx].clone()
                        }
                        Param::StmtOutputNamed(stmt_idx, col) => {
                            let sql = &executed_sql[idx];
                            let stmt = txn.prepare_cached(sql)?;
                            let col_idx = stmt.column_index(&col).unwrap();

                            executed_rows[stmt_idx][col_idx].clone()
                        }
                    };

                    stmt.raw_bind_parameter(idx + 1, rparam)
                        .map_err(DbError::Rusqlite)?;
                }

                let column_count = stmt.column_count();

                let (result, first_row) = if column_count > 0 {
                    let mut rows = stmt.raw_query();
                    let mut row_count = 0;
                    let mut first_row = vec![];

                    let result = loop {
                        match rows.next() {
                            Ok(Some(row)) => {
                                if row_count == 0 {
                                    for i in 0..column_count {
                                        first_row.push(row.get(i).unwrap());
                                    }
                                }

                                row_count += 1;
                            }
                            Ok(None) => {
                                break Ok(row_count);
                            }
                            Err(err) => {
                                break Err(DbError::Rusqlite(err));
                            }
                        };
                    };

                    (result, first_row)
                } else {
                    (stmt.raw_execute().map_err(DbError::Rusqlite), vec![])
                };

                executed_sql.push(sql);
                executed_rows.push(first_row);
                output.push(result);
            }

            if output.iter().any(|result| result.is_err()) {
                txn.rollback()?;
            } else {
                txn.commit()?;
            }

            Ok(output)
        })
        .await?
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
