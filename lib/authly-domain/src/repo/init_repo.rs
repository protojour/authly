//! things that must be done at app startup to sync potential code changes and DB

use std::{borrow::Cow, collections::HashMap, time::Duration};

use authly_common::id::{AttrId, DirectoryId, Id128DynamicArrayConv, PropId, ServiceId};
use authly_db::{param::ToBlob, params, Db, DbError, DbResult, FromRow};
use fnv::FnvHashMap;
use indoc::indoc;
use tracing::info;

use crate::{
    builtins::Builtins,
    directory::DirKey,
    id::{BuiltinAttr, BuiltinProp},
    IsLeaderDb,
};

#[derive(Debug)]
enum InitDbError {
    Missing(Vec<Missing>),
    Db(DbError),
}

#[derive(Debug)]
enum Missing {
    DirNamespace,
    Prop(BuiltinProp),
    Attr(BuiltinAttr),
}

impl From<DbError> for InitDbError {
    fn from(err: DbError) -> Self {
        InitDbError::Db(err)
    }
}

pub async fn load_authly_builtins(deps: &impl Db, is_leader: IsLeaderDb) -> DbResult<Builtins> {
    if is_leader.0 {
        match try_load_authly_builtins(deps).await {
            Ok(builtins) => {
                info!("builtins up to date");
                Ok(builtins)
            }
            Err(InitDbError::Db(err)) => Err(err),
            Err(InitDbError::Missing(missing)) => {
                write_builtins(deps, missing).await?;

                Ok(try_load_authly_builtins(deps)
                    .await
                    .expect("missing after write"))
            }
        }
    } else {
        loop {
            match try_load_authly_builtins(deps).await {
                Ok(builtins) => return Ok(builtins),
                Err(InitDbError::Db(err)) => return Err(err),
                Err(_) => {
                    info!("waiting for leader to create builtins");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }
}

async fn write_builtins<D: Db>(deps: &D, missing: Vec<Missing>) -> DbResult<()> {
    info!("writing builtins: {missing:?}");

    let mut stmts: Vec<(Cow<'static, str>, Vec<<D as Db>::Param>)> =
        Vec::with_capacity(missing.len());
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let dir_key = D::stmt_column(0, 0);
    let ns_key = D::stmt_column(1, 0);

    stmts.push((
        "INSERT INTO directory (id, kind, label) VALUES ($1, 'authly', 'authly') ON CONFLICT DO NOTHING RETURNING key".into(),
        params!(DirectoryId::from_uint(0).to_blob()),
    ));
    stmts.push((
        "INSERT INTO namespace (dir_key, id, upd, label) VALUES ($1, $2, $3, 'authly') ON CONFLICT DO NOTHING RETURNING key"
            .into(),
        params!(dir_key.clone(), ServiceId::from_uint(0).to_blob(), now),
    ));

    for m in missing {
        match m {
            Missing::DirNamespace => {}
            Missing::Prop(builtin_prop) => {
                stmts.push((
                    "INSERT INTO prop (dir_key, ns_key, id, kind, upd, label) VALUES ($1, $2, $3, 'ent', $4, $5) ON CONFLICT DO NOTHING RETURNING key".into(),
                    params!(dir_key.clone(), ns_key.clone(), PropId::from(builtin_prop).to_blob(), now, builtin_prop.label())
                ));
            }
            Missing::Attr(builtin_attr) => {
                if !BuiltinProp::AuthlyRole.attributes().contains(&builtin_attr) {
                    todo!("needs a different design if other builtin properties get attributes");
                }

                stmts.push((
                    indoc! {
                        "INSERT INTO attr (dir_key, prop_key, id, upd, label)
                        VALUES ($1, (SELECT key FROM prop WHERE id = $2), $3, $4, $5)
                        ON CONFLICT DO NOTHING RETURNING key"
                    }
                    .into(),
                    params!(
                        dir_key.clone(),
                        PropId::from(BuiltinProp::AuthlyRole).to_blob(),
                        AttrId::from(builtin_attr).to_blob(),
                        now,
                        builtin_attr.label()
                    ),
                ));
            }
        }
    }

    deps.transact(stmts).await?;

    Ok(())
}

async fn try_load_authly_builtins(deps: &impl Db) -> Result<Builtins, InitDbError> {
    let mut missing = vec![];

    let Some(dir_namespace_row) = deps
        .query_map_opt::<DirNamespaceRow>(
            indoc! {
                "
                SELECT directory.key as dir_key, namespace.key AS ns_key
                FROM directory
                JOIN namespace ON namespace.dir_key = directory.key
                WHERE namespace.label = 'authly'
                "
            }
            .into(),
            params!(),
        )
        .await?
    else {
        missing.push(Missing::DirNamespace);
        missing.extend(BuiltinProp::iter().map(Missing::Prop));
        missing.extend(BuiltinAttr::iter().map(Missing::Attr));

        return Err(InitDbError::Missing(missing));
    };

    let mut builtin_prop_rows: HashMap<PropId, i64> = deps
        .query_map::<BuiltinKey<PropId>>(
            "SELECT id, key FROM prop WHERE dir_key = $1".into(),
            params!(dir_namespace_row.dir_key.0),
        )
        .await?
        .into_iter()
        .map(|row| (row.0, row.1))
        .collect();

    let mut prop_keys = FnvHashMap::default();

    for builtin_prop in BuiltinProp::iter() {
        let Some(key) = builtin_prop_rows.remove(&builtin_prop.into()) else {
            missing.push(Missing::Prop(builtin_prop));
            continue;
        };

        prop_keys.insert(builtin_prop, key);
    }

    let mut builtin_attr_rows: HashMap<AttrId, i64> = deps
        .query_map::<BuiltinKey<AttrId>>(
            "SELECT id, key FROM attr WHERE dir_key = $1".into(),
            params!(dir_namespace_row.dir_key.0),
        )
        .await?
        .into_iter()
        .map(|row| (row.0, row.1))
        .collect();

    let mut attr_keys = FnvHashMap::default();

    for builtin_attr in BuiltinAttr::iter() {
        let Some(key) = builtin_attr_rows.remove(&builtin_attr.into()) else {
            missing.push(Missing::Attr(builtin_attr));
            continue;
        };

        attr_keys.insert(builtin_attr, key);
    }

    if missing.is_empty() {
        Ok(Builtins {
            authly_dir_key: dir_namespace_row.dir_key,
            authly_namespace_key: dir_namespace_row.ns_key,
            prop_keys,
            attr_keys,
        })
    } else {
        Err(InitDbError::Missing(missing))
    }
}

struct DirNamespaceRow {
    dir_key: DirKey,
    ns_key: i64,
}

impl FromRow for DirNamespaceRow {
    fn from_row(row: &mut impl authly_db::Row) -> Self {
        Self {
            dir_key: DirKey(row.get_int("dir_key")),
            ns_key: row.get_int("ns_key"),
        }
    }
}

struct BuiltinKey<T>(T, i64);

impl<T: Id128DynamicArrayConv> FromRow for BuiltinKey<T> {
    fn from_row(row: &mut impl authly_db::Row) -> Self {
        Self(row.get_id("id"), row.get_int("key"))
    }
}
