use authly_db::Row;

pub struct RusqliteRowBorrowed<'a, 'b> {
    pub(super) row: &'a rusqlite::Row<'b>,
}

impl Row for RusqliteRowBorrowed<'_, '_> {
    fn get_int(&mut self, idx: &str) -> i64 {
        self.row.get(idx).unwrap()
    }

    fn get_opt_int(&mut self, idx: &str) -> Option<i64> {
        self.row.get(idx).unwrap()
    }

    fn get_text(&mut self, idx: &str) -> String {
        self.row.get(idx).unwrap()
    }

    fn get_opt_text(&mut self, idx: &str) -> Option<String> {
        self.row.get(idx).unwrap()
    }

    fn get_blob(&mut self, idx: &str) -> Vec<u8> {
        self.row.get(idx).unwrap()
    }

    fn get_blob_array<const N: usize>(&mut self, idx: &str) -> [u8; N] {
        self.row.get(idx).unwrap()
    }
}
