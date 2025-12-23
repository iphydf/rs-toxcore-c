use crate::dag::{
    ChainKey, EncryptionKey, EphemeralX25519Pk, EphemeralX25519Sk, KConv, MacKey, MessageKey,
    NodeMac, PhysicalDevicePk, PhysicalDeviceSk, SharedSecretKey,
};
use blake3::derive_key;
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

#[derive(Clone)]
pub struct ConversationKeys {
    pub k_conv: KConv,
    pub k_enc: EncryptionKey,
    pub k_mac: MacKey,
}

/// Converts an Ed25519 public key to an X25519 public key.
/// This is needed because Tox IDs are Ed25519 keys, but KeyWrap uses X25519 DH.
fn ed25519_pk_to_x25519(ed_pk: &[u8; 32]) -> Option<XPublicKey> {
    let ed_point = CompressedEdwardsY(*ed_pk).decompress()?;
    let x_bytes = ed_point.to_montgomery().0;
    Some(XPublicKey::from(x_bytes))
}

/// Converts an Ed25519 secret seed to an X25519 secret key (scalar).
/// This follows the standard RFC 8032 and libsodium conversion.
pub fn ed25519_sk_to_x25519(ed_sk: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(ed_sk);
    let hash = hasher.finalize();
    let mut x_sk = [0u8; 32];
    x_sk.copy_from_slice(&hash[0..32]);

    // Clamping
    x_sk[0] &= 248;
    x_sk[31] &= 127;
    x_sk[31] |= 64;

    x_sk
}

impl ConversationKeys {
    pub fn derive(k_conv: &KConv) -> Self {
        let k_enc = derive_key("merkle-tox v1 enc", k_conv.as_bytes());
        let k_mac = derive_key("merkle-tox v1 mac", k_conv.as_bytes());
        tracing::debug!(
            "Derived keys from {}: k_mac={}",
            hex::encode(k_conv.as_bytes()),
            hex::encode(k_mac)
        );
        Self {
            k_conv: k_conv.clone(),
            k_enc: EncryptionKey::from(k_enc),
            k_mac: MacKey::from(k_mac),
        }
    }

    /// Wraps (encrypts) the conversation key for a recipient using X25519 DH.
    pub fn wrap_for(
        &self,
        self_dh_sk: &[u8; 32],
        recipient_pk: &PhysicalDevicePk,
    ) -> Option<Vec<u8>> {
        let secret = StaticSecret::from(*self_dh_sk);
        let recipient_x25519 = ed25519_pk_to_x25519(recipient_pk.as_bytes())?;
        let shared_secret = secret.diffie_hellman(&recipient_x25519);

        let k_wrap = derive_key("merkle-tox v1 key-wrap", shared_secret.as_bytes());
        let mut payload = *self.k_conv.as_bytes();

        // Use a zero nonce for KeyWrap as the DH secret is unique per pair
        let mut cipher = ChaCha20::new(&k_wrap.into(), &[0u8; 12].into());
        cipher.apply_keystream(&mut payload);

        Some(payload.to_vec())
    }

    /// Unwraps (decrypts) a conversation key sent to us.
    pub fn unwrap_from(
        self_dh_sk: &[u8; 32],
        author_pk: &PhysicalDevicePk,
        ciphertext: &[u8],
    ) -> Option<KConv> {
        if ciphertext.len() != 32 {
            return None;
        }

        let secret = StaticSecret::from(*self_dh_sk);
        let author_x25519 = ed25519_pk_to_x25519(author_pk.as_bytes())?;
        let shared_secret = secret.diffie_hellman(&author_x25519);

        let k_wrap = derive_key("merkle-tox v1 key-wrap", shared_secret.as_bytes());
        let mut payload = [0u8; 32];
        payload.copy_from_slice(ciphertext);

        let mut cipher = ChaCha20::new(&k_wrap.into(), &[0u8; 12].into());
        cipher.apply_keystream(&mut payload);

        Some(KConv::from(payload))
    }

    /// Unwraps (decrypts) a conversation key sent to us using a raw X25519 public key.
    pub fn unwrap_from_x25519(
        self_dh_sk: &[u8; 32],
        author_x25519_pk: &[u8; 32],
        ciphertext: &[u8],
    ) -> Option<KConv> {
        if ciphertext.len() != 32 {
            return None;
        }

        let secret = StaticSecret::from(*self_dh_sk);
        let author_x25519 = XPublicKey::from(*author_x25519_pk);
        let shared_secret = secret.diffie_hellman(&author_x25519);

        let k_wrap = derive_key("merkle-tox v1 key-wrap", shared_secret.as_bytes());
        let mut payload = [0u8; 32];
        payload.copy_from_slice(ciphertext);

        let mut cipher = ChaCha20::new(&k_wrap.into(), &[0u8; 12].into());
        cipher.apply_keystream(&mut payload);

        Some(KConv::from(payload))
    }

    pub fn calculate_mac(&self, data: &[u8]) -> NodeMac {
        tracing::debug!(
            "Calculating MAC with k_mac: {}",
            hex::encode(self.k_mac.as_bytes())
        );
        tracing::debug!(
            "  Data prefix: {}",
            hex::encode(&data[..std::cmp::min(data.len(), 16)])
        );
        NodeMac::from(*blake3::keyed_hash(self.k_mac.as_bytes(), data).as_bytes())
    }

    pub fn verify_mac(&self, data: &[u8], mac: &NodeMac) -> bool {
        let calculated = self.calculate_mac(data);
        let res: bool = calculated.as_bytes().ct_eq(mac.as_bytes()).into();
        if !res {
            tracing::debug!(
                "MAC verification failed with k_mac prefix: {}",
                hex::encode(&self.k_mac.as_bytes()[..8])
            );
            tracing::debug!("  Calculated:  {:?}", calculated.as_bytes());
            tracing::debug!("  Expected:    {:?}", mac.as_bytes());
            tracing::debug!("  Data len:    {}", data.len());
            tracing::debug!("  Data hex:    {}", hex::encode(data));
        }
        res
    }

    /// Encrypts data using ChaCha20.
    /// In Merkle-Tox, the nonce is derived from the node's hash or topological rank
    /// to ensure determinism and privacy, or provided externally.
    /// For WireNode obfuscation, we use the first 12 bytes of the first parent hash as a nonce,
    /// or a zero nonce if no parents exist (Genesis).
    pub fn encrypt(&self, nonce: &[u8; 12], data: &mut [u8]) {
        let mut cipher = ChaCha20::new(self.k_enc.as_bytes().into(), nonce.into());
        cipher.apply_keystream(data);
    }

    /// Decrypts data using ChaCha20.
    pub fn decrypt(&self, nonce: &[u8; 12], data: &mut [u8]) {
        self.encrypt(nonce, data); // ChaCha20 is symmetric
    }

    /// Decrypts a node payload using a nonce derived from its MAC.
    pub fn decrypt_payload_with_mac(&self, mac: &NodeMac, data: &mut [u8]) {
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&mac.as_bytes()[0..12]);
        self.decrypt(&nonce, data);
    }

    /// Encrypts a node payload using a nonce derived from its MAC.
    pub fn encrypt_payload_with_mac(&self, mac: &NodeMac, data: &mut [u8]) {
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&mac.as_bytes()[0..12]);
        self.encrypt(&nonce, data);
    }
}

/// Computes the X3DH shared secret for the initiator.
pub fn x3dh_derive_secret_initiator(
    self_device_sk: &PhysicalDeviceSk,
    self_ephemeral_sk: &EphemeralX25519Sk,
    peer_device_pk: &PhysicalDevicePk,
    peer_signed_pre_pk: &EphemeralX25519Pk,
    peer_one_time_pk: Option<&EphemeralX25519Pk>,
) -> Option<SharedSecretKey> {
    use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

    let i_a = StaticSecret::from(ed25519_sk_to_x25519(self_device_sk.as_bytes()));
    let e_a = StaticSecret::from(*self_ephemeral_sk.as_bytes());

    let i_b = ed25519_pk_to_x25519(peer_device_pk.as_bytes())?;
    let spk_b = XPublicKey::from(*peer_signed_pre_pk.as_bytes());

    let dh1 = i_a.diffie_hellman(&spk_b);
    let dh2 = e_a.diffie_hellman(&i_b);
    let dh3 = e_a.diffie_hellman(&spk_b);

    let mut material = Vec::with_capacity(32 * 4);
    material.extend_from_slice(dh1.as_bytes());
    material.extend_from_slice(dh2.as_bytes());
    material.extend_from_slice(dh3.as_bytes());

    if let Some(opk_b_pk) = peer_one_time_pk {
        let opk_b = XPublicKey::from(*opk_b_pk.as_bytes());
        let dh4 = e_a.diffie_hellman(&opk_b);
        material.extend_from_slice(dh4.as_bytes());
    }

    Some(SharedSecretKey::from(derive_key(
        "merkle-tox v1 x3dh",
        &material,
    )))
}

/// Computes the X3DH shared secret for the recipient.
pub fn x3dh_derive_secret_recipient(
    self_device_sk: &PhysicalDeviceSk,
    self_signed_pre_sk: &EphemeralX25519Sk,
    peer_device_pk: &PhysicalDevicePk,
    peer_ephemeral_pk: &EphemeralX25519Pk,
    self_one_time_sk: Option<&EphemeralX25519Sk>,
) -> Option<SharedSecretKey> {
    use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

    let i_b = StaticSecret::from(ed25519_sk_to_x25519(self_device_sk.as_bytes()));
    let spk_b = StaticSecret::from(*self_signed_pre_sk.as_bytes());

    let i_a = ed25519_pk_to_x25519(peer_device_pk.as_bytes())?;
    let e_a = XPublicKey::from(*peer_ephemeral_pk.as_bytes());

    let dh1 = spk_b.diffie_hellman(&i_a);
    let dh2 = i_b.diffie_hellman(&e_a);
    let dh3 = spk_b.diffie_hellman(&e_a);

    let mut material = Vec::with_capacity(32 * 4);
    material.extend_from_slice(dh1.as_bytes());
    material.extend_from_slice(dh2.as_bytes());
    material.extend_from_slice(dh3.as_bytes());

    if let Some(opk_b_sk) = self_one_time_sk {
        let opk_b_sk = StaticSecret::from(*opk_b_sk.as_bytes());
        let dh4 = opk_b_sk.diffie_hellman(&e_a);
        material.extend_from_slice(dh4.as_bytes());
    }

    Some(SharedSecretKey::from(derive_key(
        "merkle-tox v1 x3dh",
        &material,
    )))
}

/// Derives the next chain key from the current one.
pub fn ratchet_step(chain_key: &ChainKey) -> ChainKey {
    ChainKey::from(derive_key(
        "merkle-tox v1 ratchet-step",
        chain_key.as_bytes(),
    ))
}

/// Derives the message encryption key from the current chain key.
pub fn ratchet_message_key(chain_key: &ChainKey) -> MessageKey {
    MessageKey::from(derive_key(
        "merkle-tox v1 message-key",
        chain_key.as_bytes(),
    ))
}

/// Merges multiple parent chain keys into a new initial chain key.
pub fn ratchet_merge(parent_keys: &[ChainKey]) -> ChainKey {
    let mut sorted = parent_keys.to_vec();
    sorted.sort_unstable();
    let mut material = Vec::with_capacity(sorted.len() * 32);
    for key in sorted {
        material.extend_from_slice(key.as_bytes());
    }
    ChainKey::from(derive_key("merkle-tox v1 ratchet-merge", &material))
}
