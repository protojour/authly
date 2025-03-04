mod end2end;
mod test_access_control;
mod test_authly_connect;
mod test_authority_mandate;
mod test_demo;
mod test_docs_clause_examples;
mod test_docs_full_example;
mod test_document;
mod test_metadata;
mod test_tls;
mod test_ultradb;
mod test_webauthn;

#[test]
fn directory_changed_serde() {
    use authly_common::id::DirectoryId;
    use authly_domain::bus::ClusterMessage;

    let msg0 = ClusterMessage::DirectoryChanged {
        dir_id: DirectoryId::random(),
    };
    let json = serde_json::to_vec(&msg0).unwrap();
    let msg1: ClusterMessage = serde_json::from_slice(&json).unwrap();

    assert_eq!(msg0, msg1);
}
