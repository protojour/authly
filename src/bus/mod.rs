pub mod cluster;
pub mod handler;
pub mod service_events;

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
