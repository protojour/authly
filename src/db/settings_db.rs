use std::borrow::Cow;

use authly_common::id::DirectoryId;
use authly_db::{Db, DbResult, Row, TryFromRow};
use hiqlite::params;

use crate::settings::{Setting, Settings};

struct LocalSetting {
    #[expect(unused)]
    dir_id: DirectoryId,
    setting: Setting,
    value: String,
}

#[derive(Debug)]
struct DbSettingError(#[allow(unused)] String);

impl TryFromRow for LocalSetting {
    type Error = DbSettingError;

    fn try_from_row(row: &mut impl Row) -> Result<Self, Self::Error> {
        let setting = row.get_int("setting") as u16;
        let Ok(setting) = Setting::try_from(setting) else {
            return Err(DbSettingError(format!(
                "setting number {setting} is invalid, ignoring"
            )));
        };

        Ok(LocalSetting {
            dir_id: row.get_id("dir_id"),
            setting,
            value: row.get_text("value"),
        })
    }
}

pub async fn load_local_settings(deps: &impl Db) -> DbResult<Settings> {
    let local_settings = deps
        .query_filter_map(
            "SELECT dir_id, setting, value FROM local_setting".into(),
            params!(),
        )
        .await?;

    let mut settings = Settings::default();

    for LocalSetting {
        // TODO: Sort settings based on directory importance:
        dir_id: _,
        setting,
        value,
    } in local_settings
    {
        if let Err(err) = settings.try_set(setting, Cow::Owned(value)) {
            tracing::error!(?err, "setting {setting:?} value is invalid, ignoring");
        }
    }

    Ok(settings)
}
