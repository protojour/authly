use authly::{
    access_token,
    cert::Cert,
    session::{Session, SessionToken},
    DynamicConfig,
};
use authly_common::id::{Eid, ObjId};
use criterion::{criterion_group, criterion_main, Criterion};
use fnv::FnvHashSet;
use time::{Duration, OffsetDateTime};

pub fn authly_benchmark(c: &mut Criterion) {
    let local_ca = Cert::new_authly_ca();
    let jwt_decoding_key = {
        let (_, x509_cert) = x509_parser::parse_x509_certificate(&local_ca.der).unwrap();
        jsonwebtoken::DecodingKey::from_ec_der(&x509_cert.public_key().subject_public_key.data)
    };
    let dynamic_config = DynamicConfig {
        local_ca,
        jwt_decoding_key,
    };
    let session = Session {
        token: SessionToken::new_random(),
        eid: Eid::random(),
        expires_at: OffsetDateTime::now_utc() + Duration::days(42),
    };
    let user_attributes = FnvHashSet::from_iter([ObjId::random(), ObjId::random()]);

    c.bench_function("generate_access_token", |b| {
        b.iter(|| {
            access_token::create_access_token(&session, user_attributes.clone(), &dynamic_config)
                .unwrap();
        })
    });
}

criterion_group!(benches, authly_benchmark);
criterion_main!(benches);
