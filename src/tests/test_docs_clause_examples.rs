use super::compile_and_apply_doc_dir;
use crate::test_support::TestCtx;

#[test_log::test(tokio::test)]
async fn smoketest_docs_clause_examples() {
    let ctx = TestCtx::new().inmemory_db().await.supreme_instance().await;

    compile_and_apply_doc_dir("docs/src/examples/clause_examples".into(), &ctx)
        .await
        .unwrap();
}
