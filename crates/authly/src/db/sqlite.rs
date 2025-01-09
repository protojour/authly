//! sqlite integration with the `Db` trait

use core::str;
use std::{borrow::Cow, collections::HashMap, sync::RwLock};

use hiqlite::{Param, Params};
use rusqlite::{
    params_from_iter,
    types::{ToSqlOutput, Value},
    Column, ParamsFromIter,
};

use super::{Db, DbError, Row};

#[cfg(test)]
pub async fn test_inmemory_db() -> RwLock<rusqlite::Connection> {
    use crate::Migrations;

    let mut conn = rusqlite::Connection::open_in_memory().unwrap();
    sqlite_migrate::<Migrations>(&mut conn).await.unwrap();

    RwLock::new(conn)
}

#[cfg(test)]
pub async fn sqlite_migrate<T: rust_embed::RustEmbed>(
    conn: &mut rusqlite::Connection,
) -> Result<(), DbError> {
    let mut files: Vec<_> = T::iter().collect();
    files.sort();

    let txn = conn.transaction().map_err(DbError::Rusqlite)?;

    for file in files {
        let migration = T::get(&file).unwrap();
        txn.execute_batch(str::from_utf8(&migration.data).unwrap())
            .map_err(DbError::Rusqlite)?;
    }

    txn.commit().map_err(DbError::Rusqlite)?;

    Ok(())
}

impl Db for RwLock<rusqlite::Connection> {
    type Row<'a> = RusqliteRow;

    async fn query_raw(
        &self,
        stmt: Cow<'static, str>,
        params: Params,
    ) -> Result<Vec<Self::Row<'_>>, DbError> {
        let conn = self.read().unwrap();
        let mut stmt = conn.prepare(&stmt).map_err(DbError::Rusqlite)?;
        let columns: Vec<_> = stmt
            .columns()
            .iter()
            .map(RusqliteColumn::from_column)
            .collect();

        let mut rows = stmt
            .query(rusqlite_params(params))
            .map_err(DbError::Rusqlite)?;

        let mut output = vec![];

        while let Some(row) = rows.next().map_err(DbError::Rusqlite)? {
            output.push(RusqliteRow::from_rusqlite(row, &columns));
        }

        Ok(output)
    }

    async fn execute(&self, sql: Cow<'static, str>, params: Params) -> Result<usize, DbError> {
        let conn = self.read().unwrap();
        Ok(
            rusqlite::Connection::execute(&conn, &sql, rusqlite_params(params))
                .map_err(DbError::Rusqlite)?,
        )
    }

    async fn txn<C, Q>(&self, sql: Q) -> Result<Vec<Result<usize, DbError>>, DbError>
    where
        Q: IntoIterator<Item = (C, Params)>,
        C: Into<Cow<'static, str>>,
    {
        let mut conn = self.write().unwrap();
        let txn = conn.transaction().map_err(DbError::Rusqlite)?;

        let mut output = vec![];

        for (query, params) in sql {
            output.push(
                txn.execute(&query.into(), rusqlite_params(params))
                    .map_err(DbError::Rusqlite),
            );
        }

        txn.commit().map_err(DbError::Rusqlite)?;

        Ok(output)
    }
}

struct RusqliteColumn {
    name: String,
    ty: RusqliteColumnType,
}

enum RusqliteColumnType {
    Expr,
    Integer,
    Real,
    Text,
    Blob,
}

impl RusqliteColumn {
    fn from_column(column: &Column) -> Self {
        let name = column.name();
        let ty = match column.decl_type() {
            Some("TEXT") => RusqliteColumnType::Text,
            Some("BLOB" | "") => RusqliteColumnType::Blob,
            Some("REAL") => RusqliteColumnType::Real,
            Some(t) if t.starts_with("INT") => RusqliteColumnType::Integer,
            Some(t) if t.contains("INT") || t.contains("int") => RusqliteColumnType::Integer,
            Some(t) if t.contains("CHAR") || t.contains("CLOB") => RusqliteColumnType::Text,
            Some(_) => RusqliteColumnType::Integer,
            None => RusqliteColumnType::Expr,
        };

        Self {
            name: name.to_string(),
            ty,
        }
    }
}

pub struct RusqliteRow {
    entries: HashMap<String, rusqlite::types::Value>,
}

impl RusqliteRow {
    fn from_rusqlite(row: &rusqlite::Row, columns: &[RusqliteColumn]) -> Self {
        use rusqlite::types::Value;
        let mut entries = HashMap::with_capacity(columns.len());

        for (idx, col) in columns.iter().enumerate() {
            let val = match &col.ty {
                RusqliteColumnType::Expr => todo!("expr"),
                RusqliteColumnType::Integer => {
                    row.get(idx).map(Value::Integer).unwrap_or(Value::Null)
                }
                RusqliteColumnType::Real => row.get(idx).map(Value::Real).unwrap_or(Value::Null),
                RusqliteColumnType::Text => row.get(idx).map(Value::Text).unwrap_or(Value::Null),
                RusqliteColumnType::Blob => row.get(idx).map(Value::Blob).unwrap_or(Value::Null),
            };

            entries.insert(col.name.clone(), val);
        }

        Self { entries }
    }
}

impl<'a> Row for RusqliteRow {
    fn get_int(&mut self, idx: &str) -> i64 {
        match self.entries.remove(idx).unwrap() {
            rusqlite::types::Value::Integer(i) => i,
            _ => panic!(),
        }
    }

    fn get_opt_int(&mut self, idx: &str) -> Option<i64> {
        match self.entries.remove(idx) {
            Some(rusqlite::types::Value::Integer(i)) => Some(i),
            _ => None,
        }
    }

    fn get_text(&mut self, idx: &str) -> String {
        match self.entries.remove(idx).unwrap() {
            rusqlite::types::Value::Text(t) => t,
            _ => panic!(),
        }
    }

    fn get_opt_text(&mut self, idx: &str) -> Option<String> {
        match self.entries.remove(idx) {
            Some(rusqlite::types::Value::Text(t)) => Some(t),
            _ => None,
        }
    }

    fn get_blob(&mut self, idx: &str) -> Vec<u8> {
        match self.entries.remove(idx).unwrap() {
            rusqlite::types::Value::Blob(b) => b,
            _ => panic!(),
        }
    }
}

fn rusqlite_params(
    params: hiqlite::Params,
) -> ParamsFromIter<impl Iterator<Item = ToSqlOutput<'static>>> {
    params_from_iter(params.into_iter().map(|p| {
        ToSqlOutput::Owned(match p {
            Param::Null => Value::Null,
            Param::Integer(i) => Value::Integer(i),
            Param::Real(r) => Value::Real(r),
            Param::Text(t) => Value::Text(t),
            Param::Blob(vec) => Value::Blob(vec),
        })
    }))
}
