use merkle_tox_core::dag::{ConversationId, LogicalIdentityPk, Permissions, PhysicalDevicePk};
use merkle_tox_core::identity::IdentityManager;
use merkle_tox_core::testing::{make_cert, random_signing_key};

#[test]
fn test_identity_authorization() {
    let logical_sk = random_signing_key();
    let logical_pk = LogicalIdentityPk::from(logical_sk.verifying_key().to_bytes());

    let device_sk = random_signing_key();
    let device_pk = PhysicalDevicePk::from(device_sk.verifying_key().to_bytes());

    let expires_at: i64 = 2000000000000;
    let permissions = Permissions::ALL;

    let cert = make_cert(&logical_sk, device_pk, permissions, expires_at);

    let conv_id = ConversationId::from([0xAAu8; 32]);
    let mut manager = IdentityManager::new();
    manager
        .authorize_device(conv_id, logical_pk, &cert, 1000000000000, 0)
        .expect("Should authorize");

    assert!(manager.is_authorized(conv_id, &device_pk, &logical_pk, 1100000000000, 0));
    assert!(!manager.is_authorized(conv_id, &device_pk, &logical_pk, 3000000000000, 0)); // Expired
}

// end of file
