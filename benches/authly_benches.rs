use authly::{
    access_token,
    cert::{key_pair, MakeSigningRequest},
    session::{Session, SessionToken},
    TlsParams,
};
use authly_common::id::{Eid, ObjId};
use criterion::{criterion_group, criterion_main, Criterion};
use fnv::FnvHashSet;
use time::{Duration, OffsetDateTime};

pub fn authly_benchmark(c: &mut Criterion) {
    let local_ca = key_pair().authly_ca().self_signed();
    let identity = key_pair().authly_ca().self_signed();
    let tls_params = TlsParams::from_keys(local_ca, identity);
    let session = Session {
        token: SessionToken::new_random(),
        eid: Eid::random(),
        expires_at: OffsetDateTime::now_utc() + Duration::days(42),
    };
    let user_attributes = FnvHashSet::from_iter([ObjId::random(), ObjId::random()]);

    c.bench_function("generate_access_token", |b| {
        b.iter(|| {
            access_token::create_access_token(&session, user_attributes.clone(), &tls_params)
                .unwrap();
        })
    });
}

criterion_group!(benches, authly_benchmark);
criterion_main!(benches);
