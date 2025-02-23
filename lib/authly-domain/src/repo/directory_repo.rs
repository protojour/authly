use authly_common::id::{DirectoryId, ServiceId};
use authly_db::{param::ToBlob, params, Db, DbResult, FromRow, Row};

use crate::directory::DirKey;

pub async fn query_dir_key(deps: &impl Db, dir_id: DirectoryId) -> DbResult<Option<DirKey>> {
    deps.query_map_opt::<DirKey>(
        "SELECT key FROM directory WHERE id = $1".into(),
        params!(dir_id.to_blob()),
    )
    .await
}

pub struct DbDirectoryService {
    pub svc_eid: ServiceId,
}

impl FromRow for DbDirectoryService {
    fn from_row(row: &mut impl Row) -> Self {
        Self {
            svc_eid: row.get_id("svc_eid"),
        }
    }
}

impl DbDirectoryService {
    pub async fn query(deps: &impl Db, dir_key: DirKey) -> DbResult<Vec<Self>> {
        deps.query_map(
            // FIXME: unindexed query
            "SELECT svc_eid FROM svc WHERE dir_key = $1".into(),
            params!(dir_key.0),
        )
        .await
    }
}
