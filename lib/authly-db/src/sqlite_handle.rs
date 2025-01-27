//! Message passing system around rusqlite to make it Sync

use core::str;
use std::{borrow::Cow, fmt::Debug};

use hiqlite::Params;
use rusqlite::Connection;
use tokio::{
    sync::{mpsc, oneshot},
    task::LocalSet,
};
use tracing::debug;

use crate::{
    sqlite::{sqlite_execute, sqlite_query_raw, sqlite_txn, RusqliteRow},
    Db, DbError,
};

/// An sqlite (rusqlite) wrapper that is Send + Sync by using message passing.
///
/// The actual [rusqlite::Connection] interaction will happen on a dedicated thread.
#[derive(Clone)]
pub struct SqliteHandle {
    msg_tx: mpsc::Sender<Message>,
}

enum Message {
    QueryRaw {
        stmt: Cow<'static, str>,
        params: Params,
        respond: oneshot::Sender<Result<Vec<RusqliteRow>, DbError>>,
    },
    Execute {
        sql: Cow<'static, str>,
        params: Params,
        respond: oneshot::Sender<Result<usize, DbError>>,
    },
    Txn {
        sql: Vec<(Cow<'static, str>, Params)>,
        respond: oneshot::Sender<Result<Vec<Result<usize, DbError>>, DbError>>,
    },
}

impl SqliteHandle {
    pub fn new(mut conn: Connection) -> Self {
        let (msg_tx, mut msg_rx) = mpsc::channel::<Message>(10);

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        std::thread::spawn(move || {
            let local = LocalSet::new();

            local.spawn_local(async move {
                while let Some(msg) = msg_rx.recv().await {
                    match msg {
                        Message::QueryRaw {
                            stmt,
                            params,
                            respond,
                        } => {
                            handle_respond_err(
                                respond.send(sqlite_query_raw(&conn, stmt, params).await),
                            );
                        }
                        Message::Execute {
                            sql,
                            params,
                            respond,
                        } => {
                            handle_respond_err(
                                respond.send(sqlite_execute(&conn, sql, params).await),
                            );
                        }
                        Message::Txn { sql, respond } => {
                            handle_respond_err(respond.send(sqlite_txn(&mut conn, sql).await));
                        }
                    }
                }
            });

            // This will return once all senders are dropped and all
            // spawned tasks have returned.
            rt.block_on(local);

            debug!("SqliteHandle dropped");
        });

        Self { msg_tx }
    }
}

fn handle_respond_err<T>(result: Result<(), T>) {
    if let Err(_value) = result {
        tracing::error!("Could not respond with result");
    }
}

impl Db for SqliteHandle {
    type Row<'a> = RusqliteRow;

    async fn query_raw(
        &self,
        stmt: Cow<'static, str>,
        params: Params,
    ) -> Result<Vec<Self::Row<'_>>, DbError> {
        let (respond, recv) = oneshot::channel();
        self.msg_tx
            .send(Message::QueryRaw {
                stmt,
                params,
                respond,
            })
            .await
            .map_err(channel_err)?;
        recv.await.map_err(channel_err)?
    }

    async fn execute(&self, sql: Cow<'static, str>, params: Params) -> Result<usize, DbError> {
        let (respond, recv) = oneshot::channel();
        self.msg_tx
            .send(Message::Execute {
                sql,
                params,
                respond,
            })
            .await
            .map_err(|_| DbError::Channel)?;
        recv.await.map_err(channel_err)?
    }

    async fn txn(
        &self,
        sql: Vec<(Cow<'static, str>, Params)>,
    ) -> Result<Vec<Result<usize, DbError>>, DbError> {
        let (respond, recv) = oneshot::channel();
        self.msg_tx
            .send(Message::Txn { sql, respond })
            .await
            .map_err(channel_err)?;
        recv.await.map_err(channel_err)?
    }
}

fn channel_err<E: Debug>(err: E) -> DbError {
    tracing::error!(?err, "sqlite handle channel error");
    DbError::Channel
}
