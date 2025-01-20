//! Settings are runtime-managable dynamic configurations stored in the database.

use std::{borrow::Cow, time::Duration};

use int_enum::IntEnum;
use serde::{Deserialize, Serialize};

const SECONDS_PER_DAY: u64 = 60 * 60 * 24;

#[repr(u16)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, IntEnum, Deserialize, Serialize, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Setting {
    /// How often to rotate server certificates, in seconds
    ServerCertRotationRate = 0,
}

/// The deserialized version of the full collection of settings
#[derive(Debug)]
pub struct Settings {
    pub server_cert_rotation_rate: Duration,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            server_cert_rotation_rate: Duration::from_secs(7 * SECONDS_PER_DAY),
        }
    }
}

impl Settings {
    pub fn try_set(&mut self, setting: Setting, value: Cow<str>) -> anyhow::Result<()> {
        match setting {
            Setting::ServerCertRotationRate => {
                self.server_cert_rotation_rate = humantime::parse_duration(&value)?;
            }
        }

        Ok(())
    }
}
