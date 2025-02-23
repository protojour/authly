use std::{borrow::Cow, fmt::Debug, path::PathBuf};

use authly_db::{Db, DbError, FromRow, TryFromRow};
use deadpool::managed::{Object, Pool, PoolConfig};
use manager::SqlitePoolManager;
use param::{rusqlite_params, RusqliteParam};
use row::RusqliteRowBorrowed;
use rusqlite::types::Value;
use tracing::warn;

mod manager;
mod param;
mod row;

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
    type Param = RusqliteParam;

    async fn query_map<T>(
        &self,
        stmt: Cow<'static, str>,
        params: Vec<RusqliteParam>,
    ) -> Result<Vec<T>, DbError>
    where
        T: FromRow + Send + 'static,
    {
        let conn = self.get().await?;

        tokio::task::spawn_blocking(move || {
            let mut stmt = conn.prepare_cached(&stmt).map_err(e)?;
            let mut rows = stmt.query(rusqlite_params(params)).map_err(e)?;

            let mut output = vec![];

            while let Some(row) = rows.next().map_err(e)? {
                output.push(T::from_row(&mut RusqliteRowBorrowed { row }));
            }

            Ok(output)
        })
        .await?
    }

    async fn query_map_opt<T>(
        &self,
        stmt: Cow<'static, str>,
        params: Vec<RusqliteParam>,
    ) -> Result<Option<T>, DbError>
    where
        T: FromRow + Send + 'static,
    {
        let conn = self.get().await?;

        tokio::task::spawn_blocking(move || {
            let mut stmt = conn.prepare_cached(&stmt).map_err(e)?;
            let mut rows = stmt.query(rusqlite_params(params)).map_err(e)?;

            let mut output = None;

            if let Some(row) = rows.next().map_err(e)? {
                output = Some(T::from_row(&mut RusqliteRowBorrowed { row }));

                if rows.next().map_err(e)?.is_some() {
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
        params: Vec<RusqliteParam>,
    ) -> Result<Option<Result<T, T::Error>>, DbError>
    where
        T: TryFromRow + Send + 'static,
    {
        let conn = self.get().await?;

        tokio::task::spawn_blocking(move || {
            let mut stmt = conn.prepare_cached(&stmt).map_err(e)?;
            let mut rows = stmt.query(rusqlite_params(params)).map_err(e)?;

            let mut output = None;

            if let Some(row) = rows.next().map_err(e)? {
                output = Some(T::try_from_row(&mut RusqliteRowBorrowed { row }));

                if rows.next().map_err(e)?.is_some() {
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
        params: Vec<RusqliteParam>,
    ) -> Result<Vec<T>, DbError>
    where
        T: TryFromRow + Send + 'static,
        <T as TryFromRow>::Error: Debug,
    {
        let conn = self.get().await?;

        tokio::task::spawn_blocking(move || {
            let mut stmt = conn.prepare_cached(&stmt).map_err(e)?;
            let mut rows = stmt.query(rusqlite_params(params)).map_err(e)?;

            let mut output = vec![];

            while let Some(row) = rows.next().map_err(e)? {
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

    async fn execute(
        &self,
        stmt: Cow<'static, str>,
        params: Vec<RusqliteParam>,
    ) -> Result<usize, DbError> {
        let conn = self.get().await?;

        tokio::task::spawn_blocking(move || {
            Ok(rusqlite::Connection::execute(&conn, &stmt, rusqlite_params(params)).map_err(e)?)
        })
        .await?
    }

    async fn execute_map<T>(
        &self,
        sql: Cow<'static, str>,
        params: Vec<RusqliteParam>,
    ) -> Result<Vec<Result<T, DbError>>, DbError>
    where
        T: FromRow + Send + 'static,
    {
        let conn = self.get().await?;

        tokio::task::spawn_blocking(move || {
            let mut stmt = conn.prepare_cached(&sql).map_err(e)?;
            let mut rows = stmt.query(rusqlite_params(params)).map_err(e)?;

            let mut output = vec![];

            while let Some(row) = rows.next().map_err(e)? {
                output.push(Ok(T::from_row(&mut RusqliteRowBorrowed { row })));
            }

            Ok(output)
        })
        .await?
    }

    fn stmt_column(stmt_index: usize, column_index: usize) -> Self::Param {
        RusqliteParam::StmtOutputIndexed(stmt_index, column_index)
    }

    async fn transact(
        &self,
        sql: Vec<(Cow<'static, str>, Vec<RusqliteParam>)>,
    ) -> Result<Vec<Result<usize, DbError>>, DbError> {
        let mut conn = self.get().await?;

        tokio::task::spawn_blocking(move || {
            let txn = conn.transaction().map_err(e)?;

            let mut output = vec![];

            let mut executed_sql: Vec<Cow<'static, str>> = Vec::with_capacity(sql.len());
            let mut executed_rows: Vec<Vec<Value>> = Vec::with_capacity(sql.len());

            for (sql, params) in sql {
                let mut stmt = txn.prepare_cached(&sql).map_err(e)?;
                for (idx, param) in params.into_iter().enumerate() {
                    let rparam = match param {
                        RusqliteParam::Value(value) => value,
                        RusqliteParam::StmtOutputIndexed(stmt_idx, col_idx) => {
                            executed_rows[stmt_idx][col_idx].clone()
                        }
                    };

                    stmt.raw_bind_parameter(idx + 1, rparam).map_err(e)?;
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
                                warn!("    error: {err:?}");
                                break Err(e(err));
                            }
                        };
                    };

                    (result, first_row)
                } else {
                    (stmt.raw_execute().map_err(e), vec![])
                };

                executed_sql.push(sql);
                executed_rows.push(first_row);
                output.push(result);
            }

            if output.iter().any(|result| result.is_err()) {
                txn.rollback().map_err(e)?;
            } else {
                txn.commit().map_err(e)?;
            }

            Ok(output)
        })
        .await?
    }
}

fn e(err: rusqlite::Error) -> DbError {
    DbError::Sql(format!("{err:?}").into())
}
