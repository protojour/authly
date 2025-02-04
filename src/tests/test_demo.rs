use super::compile_and_apply_doc_dir;
use crate::test_support::TestCtx;

#[test_log::test(tokio::test)]
async fn smoketest_demo_documents() {
    let ctx = TestCtx::new().inmemory_db().await.supreme_instance().await;

    compile_and_apply_doc_dir("examples/demo".into(), &ctx)
        .await
        .unwrap();
}
