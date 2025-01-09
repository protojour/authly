use authly::{
    access_token,
    cert::Cert,
    session::{Session, SessionToken},
    DynamicConfig,
};
use authly_domain::Eid;
use criterion::{criterion_group, criterion_main, Criterion};
use fnv::FnvHashSet;
use time::{Duration, OffsetDateTime};

pub fn authly_benchmark(c: &mut Criterion) {
    let dynamic_config = DynamicConfig {
        local_ca: Cert::new_authly_ca(),
    };
    let session = Session {
        token: SessionToken::new_random(),
        eid: Eid(1337),
        expires_at: OffsetDateTime::now_utc() + Duration::days(42),
    };
    let user_attributes = FnvHashSet::from_iter([Eid(42), Eid(1337)]);

    c.bench_function("generate_access_token", |b| {
        b.iter(|| {
            access_token::create_access_token(&session, user_attributes.clone(), &dynamic_config)
                .unwrap();
        })
    });
}

criterion_group!(benches, authly_benchmark);
criterion_main!(benches);
