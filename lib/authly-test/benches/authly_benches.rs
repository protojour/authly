use authly_common::id::{AttrId, PersonaId};
use authly_domain::{
    access_token,
    ctx::LoadInstance,
    session::{Session, SessionToken},
};
use authly_test::test_ctx::TestCtx;
use criterion::{criterion_group, criterion_main, Criterion};
use fnv::FnvHashSet;
use time::{Duration, OffsetDateTime};

pub fn authly_benchmark(c: &mut Criterion) {
    let ctx = TestCtx::new().lite_instance();
    let session = Session {
        token: SessionToken::new_random(),
        eid: PersonaId::random().upcast(),
        expires_at: OffsetDateTime::now_utc() + Duration::days(42),
    };
    let user_attributes = FnvHashSet::from_iter([AttrId::random(), AttrId::random()]);
    let instance = ctx.load_instance();

    c.bench_function("generate_access_token", |b| {
        b.iter(|| {
            access_token::create_access_token(&session, user_attributes.clone(), &instance)
                .unwrap();
        })
    });
}

criterion_group!(benches, authly_benchmark);
criterion_main!(benches);
