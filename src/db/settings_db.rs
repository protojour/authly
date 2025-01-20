use std::borrow::Cow;

use authly_common::id::Eid;
use hiqlite::params;

use crate::settings::{Setting, Settings};

use super::{Convert, Db, DbResult, Row};

struct LocalSetting {
    #[expect(unused)]
    aid: Eid,
    setting: Setting,
    value: String,
}

pub async fn load_local_settings(deps: &impl Db) -> DbResult<Settings> {
    let setting_list: Vec<_> = deps
        .query_raw(
            "SELECT aid, setting, value FROM local_setting".into(),
            params!(),
        )
        .await?
        .into_iter()
        .filter_map(|mut row| {
            let setting = row.get_int("setting") as u16;
            let Ok(setting) = Setting::try_from(setting) else {
                tracing::error!("setting number {setting} is invalid, ignoring");
                return None;
            };

            Some(LocalSetting {
                aid: Eid::from_row(&mut row, "aid"),
                setting,
                value: row.get_text("value"),
            })
        })
        .collect();

    let mut settings = Settings::default();

    for LocalSetting {
        // TODO: Sort settings based on authority importance:
        aid: _,
        setting,
        value,
    } in setting_list
    {
        if let Err(err) = settings.try_set(setting, Cow::Owned(value)) {
            tracing::error!(?err, "setting {setting:?} value is invalid, ignoring");
        }
    }

    Ok(settings)
}
