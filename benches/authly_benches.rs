use authly::{
    access_token,
    ctx::{test::TestCtx, GetInstance},
    session::{Session, SessionToken},
};
use authly_common::id::{Eid, ObjId};
use criterion::{criterion_group, criterion_main, Criterion};
use fnv::FnvHashSet;
use time::{Duration, OffsetDateTime};

pub fn authly_benchmark(c: &mut Criterion) {
    let ctx = TestCtx::default().lite_instance();
    let session = Session {
        token: SessionToken::new_random(),
        eid: Eid::random(),
        expires_at: OffsetDateTime::now_utc() + Duration::days(42),
    };
    let user_attributes = FnvHashSet::from_iter([ObjId::random(), ObjId::random()]);

    c.bench_function("generate_access_token", |b| {
        b.iter(|| {
            access_token::create_access_token(
                &session,
                user_attributes.clone(),
                ctx.get_instance(),
            )
            .unwrap();
        })
    });
}

criterion_group!(benches, authly_benchmark);
criterion_main!(benches);
