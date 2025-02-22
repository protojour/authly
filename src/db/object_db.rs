use authly_common::id::{AnyId, PropId};
use authly_db::{params, param::ToBlob, Db, DbResult, FromRow};
use indoc::indoc;

pub async fn find_obj_id_by_ident_fingerprint(
    deps: &impl Db,
    ident_prop_id: PropId,
    ident_fingerprint: &[u8],
) -> DbResult<Option<AnyId>> {
    struct TypedRow(AnyId);

    impl FromRow for TypedRow {
        fn from_row(row: &mut impl authly_db::Row) -> Self {
            Self(row.get_id("obj_id"))
        }
    }

    Ok(deps
        .query_map_opt::<TypedRow>(
            indoc! {
                "
                SELECT obj_id FROM obj_ident
                WHERE prop_key = (SELECT key FROM prop WHERE id = $1) AND fingerprint = $2
                ",
            }
            .into(),
            params!(ident_prop_id.to_blob(), ident_fingerprint.to_blob()),
        )
        .await?
        .map(|row| row.0))
}
