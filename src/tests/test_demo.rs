use super::compile_and_apply_doc_dir;
use crate::{ctx::GetDb, db::init_db::load_authly_builtins, test_support::TestCtx, IsLeaderDb};

#[test_log::test(tokio::test)]
async fn smoketest_demo_documents() {
    let ctx = TestCtx::new().inmemory_db().await.supreme_instance().await;

    compile_and_apply_doc_dir("examples/demo".into(), &ctx)
        .await
        .unwrap();

    // reload authly builtins after applied doc, simulates restart
    load_authly_builtins(ctx.get_db(), IsLeaderDb(true))
        .await
        .unwrap();
}
