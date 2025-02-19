use authly_common::id::{AnyId, PropId};
use authly_db::{param::AsParam, Db, DbResult, FromRow};
use hiqlite::{params, Param};
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
                WHERE prop_id = $1 AND fingerprint = $2
                ",
            }
            .into(),
            params!(ident_prop_id.as_param(), ident_fingerprint),
        )
        .await?
        .map(|row| row.0))
}
