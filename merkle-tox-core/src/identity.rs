use crate::dag::{
    ConversationId, DelegationCertificate, Ed25519Signature, LogicalIdentityPk, Permissions,
    PhysicalDevicePk,
};
use ed25519_dalek::{Signature as DalekSignature, Signer, SigningKey, Verifier, VerifyingKey};
use parking_lot::Mutex;
use std::collections::HashMap;
use tox_proto::ToxProto;
use tox_proto::constants::MAX_AUTH_DEPTH;

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Certificate expired: {0} < {1}")]
    Expired(i64, i64),
    #[error("No valid trust path from device to logical identity")]
    NoTrustPath,
    #[error("Delegation chain too deep")]
    ChainTooDeep,
    #[error("Permission escalation: device requested permissions it does not possess")]
    PermissionEscalation,
}

#[derive(ToxProto)]
pub struct DelegationSignData {
    pub device_pk: PhysicalDevicePk,
    pub permissions: Permissions,
    pub expires_at: i64,
}

/// Signs a delegation certificate using a signing key.
pub fn sign_delegation(
    signing_key: &SigningKey,
    device_pk: PhysicalDevicePk,
    permissions: Permissions,
    expires_at: i64,
) -> DelegationCertificate {
    let sign_data = DelegationSignData {
        device_pk,
        permissions,
        expires_at,
    };
    let signed_data = tox_proto::serialize(&sign_data).expect("Failed to serialize sign data");
    let signature = Ed25519Signature::from(signing_key.sign(&signed_data).to_bytes());

    DelegationCertificate {
        device_pk,
        permissions,
        expires_at,
        signature,
    }
}

/// Verifies a delegation certificate against an issuer's public key.
pub fn verify_delegation<P: AsRef<[u8; 32]>>(
    cert: &DelegationCertificate,
    issuer_pk: P,
    now_ms: i64,
) -> Result<(), IdentityError> {
    if cert.expires_at < now_ms {
        tracing::debug!("Cert expired: {} < {}", cert.expires_at, now_ms);
        return Err(IdentityError::Expired(cert.expires_at, now_ms));
    }

    let verifying_key = VerifyingKey::from_bytes(issuer_pk.as_ref())
        .map_err(|_| IdentityError::InvalidSignature)?;
    let signature = DalekSignature::from_bytes(cert.signature.as_ref());

    let sign_data = DelegationSignData {
        device_pk: cert.device_pk,
        permissions: cert.permissions,
        expires_at: cert.expires_at,
    };
    let signed_data =
        tox_proto::serialize(&sign_data).map_err(|_| IdentityError::InvalidSignature)?;

    verifying_key
        .verify(&signed_data, &signature)
        .map_err(|e| {
            tracing::debug!(
                "Signature verification failed for {:?}: {:?}",
                cert.device_pk,
                e
            );
            IdentityError::InvalidSignature
        })?;

    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthRecord {
    pub logical_pk: LogicalIdentityPk,
    pub issuer_pk: PhysicalDevicePk, // Used for both master and devices in this context
    pub permissions: Permissions,
    pub expires_at: i64,
    pub auth_rank: u64,
}

/// A cache of verified trust paths from Physical Device PKs to Logical Identities.
pub struct IdentityManager {
    /// Mapping of (ConversationID, Device PK) -> List of Authorization Records
    authorized_devices: HashMap<(ConversationId, PhysicalDevicePk), Vec<AuthRecord>>,
    /// Mapping of (ConversationID, Logical PK) -> (Role, JoinedAt)
    logical_members: HashMap<(ConversationId, LogicalIdentityPk), (u8, i64)>,
    /// Mapping of (ConversationID, Revoked Device PK) -> RevocationRank
    revoked_devices: HashMap<(ConversationId, PhysicalDevicePk), u64>,
    /// Cache of verified paths to avoid redundant recursive checks.
    /// (ConversationID, Device PK, Logical PK, Rank) -> min_expires_at
    path_cache: Mutex<HashMap<(ConversationId, PhysicalDevicePk, LogicalIdentityPk, u64), i64>>,
}

impl Default for IdentityManager {
    fn default() -> Self {
        Self::new()
    }
}

impl IdentityManager {
    pub fn new() -> Self {
        Self {
            authorized_devices: HashMap::new(),
            logical_members: HashMap::new(),
            revoked_devices: HashMap::new(),
            path_cache: Mutex::new(HashMap::new()),
        }
    }

    /// Records a new logical member.
    pub fn add_member(
        &mut self,
        conversation_id: ConversationId,
        logical_pk: LogicalIdentityPk,
        role: u8,
        joined_at: i64,
    ) {
        self.logical_members
            .insert((conversation_id, logical_pk), (role, joined_at));
    }

    /// Removes a logical member at a specific rank.
    pub fn remove_member(
        &mut self,
        conversation_id: ConversationId,
        logical_pk: LogicalIdentityPk,
        rank: u64,
    ) {
        self.logical_members.remove(&(conversation_id, logical_pk));
        // Also revoke all their devices
        let devices_to_remove: Vec<_> = self
            .authorized_devices
            .iter()
            .filter(|((cid, _), records)| {
                cid == &conversation_id && records.iter().any(|r| r.logical_pk == logical_pk)
            })
            .map(|((_, d), _)| *d)
            .collect();
        for d in devices_to_remove {
            self.revoke_device(conversation_id, d, rank);
        }
    }

    /// Returns a list of all logical members for a conversation, sorted by PK for determinism.
    pub fn list_members(
        &self,
        conversation_id: ConversationId,
    ) -> Vec<(LogicalIdentityPk, u8, i64)> {
        let mut members: Vec<_> = self
            .logical_members
            .iter()
            .filter(|((cid, _), _)| cid == &conversation_id)
            .map(|((_, pk), (role, joined))| (*pk, *role, *joined))
            .collect();
        members.sort_by_key(|m| m.0);
        members
    }

    fn get_auth_depth(
        &self,
        conversation_id: ConversationId,
        device_pk: &PhysicalDevicePk,
        logical_pk: &LogicalIdentityPk,
        rank: u64,
    ) -> Option<usize> {
        self.get_auth_depth_recursive(conversation_id, device_pk, logical_pk, rank, 0)
    }

    fn get_auth_depth_recursive(
        &self,
        conversation_id: ConversationId,
        device_pk: &PhysicalDevicePk,
        logical_pk: &LogicalIdentityPk,
        rank: u64,
        depth: usize,
    ) -> Option<usize> {
        if depth > MAX_AUTH_DEPTH {
            return None;
        }

        if *device_pk == logical_pk.to_physical() {
            return Some(0);
        }

        if let Some(records) = self.authorized_devices.get(&(conversation_id, *device_pk)) {
            let mut min_depth = None;
            for record in records {
                if record.logical_pk == *logical_pk
                    && record.auth_rank <= rank
                    && let Some(d) = self.get_auth_depth_recursive(
                        conversation_id,
                        &record.issuer_pk,
                        logical_pk,
                        rank,
                        depth + 1,
                    )
                {
                    min_depth = Some(min_depth.map_or(d + 1, |min: usize| min.min(d + 1)));
                }
            }
            return min_depth;
        }
        None
    }

    /// Revokes a device at a specific rank.
    pub fn revoke_device(
        &mut self,
        conversation_id: ConversationId,
        device_pk: PhysicalDevicePk,
        rank: u64,
    ) {
        // Only update if the new revocation is at an earlier or same rank (though unlikely)
        self.revoked_devices
            .entry((conversation_id, device_pk))
            .and_modify(|r| *r = (*r).min(rank))
            .or_insert(rank);
        self.path_cache.lock().clear(); // Clear cache on any revocation
    }

    /// Authorizes a device using a delegation certificate at a specific rank.
    /// The issuer of the certificate must be either the Logical Identity (Master Seed)
    /// or another already authorized device with ADMIN permissions.
    pub fn authorize_device(
        &mut self,
        conversation_id: ConversationId,
        logical_pk: LogicalIdentityPk,
        cert: &DelegationCertificate,
        now_ms: i64,
        rank: u64,
    ) -> Result<(), IdentityError> {
        self.path_cache.lock().clear(); // Clear cache on any new authorization

        // 1. If the issuer is the logical_pk itself (Master Seed), it's a Level 1 delegation.
        if let Err(e) = verify_delegation(cert, logical_pk, now_ms) {
            tracing::debug!("Level 1 auth failed for {:?}: {:?}", cert.device_pk, e);
        } else {
            tracing::debug!("Level 1 auth success for {:?}", cert.device_pk);
            let records = self
                .authorized_devices
                .entry((conversation_id, cert.device_pk))
                .or_default();

            let record = AuthRecord {
                logical_pk,
                issuer_pk: logical_pk.to_physical(),
                permissions: cert.permissions,
                expires_at: cert.expires_at,
                auth_rank: rank,
            };

            if !records.contains(&record) {
                records.push(record);
            }
            return Ok(());
        }

        // 2. Otherwise, check if the issuer is an existing authorized ADMIN device.
        let mut issuer_pk = None;
        let mut issuer_perms = Permissions::NONE;
        tracing::debug!(
            "Checking Level 2+ auth for dev_pk={:?} at rank {}, candidates: {}",
            cert.device_pk,
            rank,
            self.authorized_devices.len()
        );

        // We need to find the issuer and check their effective permissions.
        for ((cid, dev_pk), records) in &self.authorized_devices {
            if cid != &conversation_id {
                continue;
            }

            for record in records {
                // The issuer must have been authorized for the correct logical identity
                // at a rank <= the current authorization node's rank.
                if record.logical_pk == logical_pk
                    && record.expires_at > now_ms
                    && record.auth_rank <= rank
                {
                    // Preliminary check for ADMIN permission in the certificate record itself
                    // (Optimization: don't do full recursive lookup if the cert doesn't even claim ADMIN)
                    if !record.permissions.contains(Permissions::ADMIN) {
                        tracing::trace!("Candidate issuer {:?} lacks ADMIN in cert", dev_pk);
                        continue;
                    }

                    if verify_delegation(cert, dev_pk, now_ms).is_ok() {
                        tracing::trace!(
                            "Candidate issuer {:?} signed the certificate, checking effective perms",
                            dev_pk
                        );
                        // Check effective permissions of the issuer
                        if let Some(effective) = self.get_permissions_recursive(
                            conversation_id,
                            dev_pk,
                            &logical_pk,
                            now_ms,
                            rank,
                            0,
                        ) {
                            if effective.contains(Permissions::ADMIN) {
                                tracing::debug!("Level 2+ auth success via issuer {:?}", dev_pk);
                                issuer_pk = Some(*dev_pk);
                                issuer_perms = effective;
                                break;
                            } else {
                                tracing::trace!(
                                    "Candidate issuer {:?} has NO effective ADMIN: {:?}",
                                    dev_pk,
                                    effective
                                );
                            }
                        } else {
                            tracing::trace!(
                                "Candidate issuer {:?} has no valid trust path at this rank",
                                dev_pk
                            );
                        }
                    }
                }
            }
            if issuer_pk.is_some() {
                break;
            }
        }

        if let Some(issuer) = issuer_pk {
            // Permission Escalation Protection:
            // A device cannot delegate permissions it does not possess.
            if !issuer_perms.contains(cert.permissions) {
                tracing::warn!(
                    "Device {:?} authorization REJECTED: escalation detected. Issuer {:?} has {:?}, tried to delegate {:?}",
                    cert.device_pk,
                    issuer,
                    issuer_perms,
                    cert.permissions
                );
                return Err(IdentityError::PermissionEscalation);
            }

            // Chain Depth Protection:
            let depth = self
                .get_auth_depth(conversation_id, &issuer, &logical_pk, rank)
                .unwrap_or(0);
            if depth + 1 > MAX_AUTH_DEPTH {
                return Err(IdentityError::ChainTooDeep);
            }

            let records = self
                .authorized_devices
                .entry((conversation_id, cert.device_pk))
                .or_default();

            let record = AuthRecord {
                logical_pk,
                issuer_pk: issuer,
                permissions: cert.permissions,
                expires_at: cert.expires_at,
                auth_rank: rank,
            };

            if !records.contains(&record) {
                records.push(record);
            }
            Ok(())
        } else {
            Err(IdentityError::NoTrustPath)
        }
    }

    /// Returns true if we have an authorization record for this device, regardless of whether it is currently valid.
    pub fn has_authorization_record(
        &self,
        conversation_id: ConversationId,
        device_pk: &PhysicalDevicePk,
    ) -> bool {
        self.authorized_devices
            .contains_key(&(conversation_id, *device_pk))
    }

    pub fn is_authorized(
        &self,
        conversation_id: ConversationId,
        device_pk: &PhysicalDevicePk,
        logical_pk: &LogicalIdentityPk,
        now_ms: i64,
        rank: u64,
    ) -> bool {
        if *device_pk == logical_pk.to_physical() {
            return true;
        }

        if let Some(&expires_at) =
            self.path_cache
                .lock()
                .get(&(conversation_id, *device_pk, *logical_pk, rank))
            && expires_at > now_ms
        {
            return true;
        }

        let res =
            self.is_authorized_recursive(conversation_id, device_pk, logical_pk, now_ms, rank, 0);
        if let Some(expires_at) = res {
            self.path_cache
                .lock()
                .insert((conversation_id, *device_pk, *logical_pk, rank), expires_at);
            true
        } else {
            false
        }
    }

    fn is_authorized_recursive(
        &self,
        conversation_id: ConversationId,
        device_pk: &PhysicalDevicePk,
        logical_pk: &LogicalIdentityPk,
        now_ms: i64,
        rank: u64,
        depth: usize,
    ) -> Option<i64> {
        if depth > MAX_AUTH_DEPTH {
            tracing::trace!(
                "Auth chain too deep or circular at depth {} for device {:?}",
                depth,
                device_pk
            );
            return None;
        }

        if *device_pk == logical_pk.to_physical() {
            return Some(i64::MAX);
        }

        if let Some(revocation_rank) = self.revoked_devices.get(&(conversation_id, *device_pk))
            && *revocation_rank <= rank
        {
            tracing::trace!(
                "Device {:?} is revoked at rank {}",
                device_pk,
                revocation_rank
            );
            return None;
        }

        if let Some(records) = self.authorized_devices.get(&(conversation_id, *device_pk)) {
            let mut max_expires = None;

            for record in records {
                if record.logical_pk != *logical_pk
                    || record.expires_at <= now_ms
                    || record.auth_rank > rank
                {
                    continue;
                }

                // Check if the issuer itself was revoked BEFORE or AT this rank.
                if let Some(issuer_rev_rank) = self
                    .revoked_devices
                    .get(&(conversation_id, record.issuer_pk))
                    && *issuer_rev_rank <= rank
                {
                    continue;
                }

                // If it's a Level 1 device (issued by Master), we have a valid path.
                if record.issuer_pk == logical_pk.to_physical() {
                    max_expires = Some(
                        max_expires
                            .map_or(record.expires_at, |max: i64| max.max(record.expires_at)),
                    );
                    continue;
                }

                // Otherwise, recursively check if the issuer is still authorized.
                if let Some(issuer_expires) = self.is_authorized_recursive(
                    conversation_id,
                    &record.issuer_pk,
                    logical_pk,
                    now_ms,
                    rank,
                    depth + 1,
                ) {
                    let path_expires = record.expires_at.min(issuer_expires);
                    max_expires =
                        Some(max_expires.map_or(path_expires, |max: i64| max.max(path_expires)));
                }
            }
            return max_expires;
        }
        None
    }

    pub fn get_permissions(
        &self,
        conversation_id: ConversationId,
        device_pk: &PhysicalDevicePk,
        logical_pk: &LogicalIdentityPk,
        now_ms: i64,
        rank: u64,
    ) -> Option<Permissions> {
        let perms =
            self.get_permissions_recursive(conversation_id, device_pk, logical_pk, now_ms, rank, 0);
        tracing::trace!(
            "Permissions for {:?} in {:?}: {:?}",
            device_pk,
            conversation_id,
            perms
        );
        perms
    }

    fn get_permissions_recursive(
        &self,
        conversation_id: ConversationId,
        device_pk: &PhysicalDevicePk,
        logical_pk: &LogicalIdentityPk,
        now_ms: i64,
        rank: u64,
        depth: usize,
    ) -> Option<Permissions> {
        if depth > MAX_AUTH_DEPTH {
            return None;
        }

        if *device_pk == logical_pk.to_physical() {
            return Some(Permissions::ALL);
        }

        if let Some(revocation_rank) = self.revoked_devices.get(&(conversation_id, *device_pk))
            && *revocation_rank <= rank
        {
            return None;
        }

        if let Some(records) = self.authorized_devices.get(&(conversation_id, *device_pk)) {
            let mut effective_perms = None;

            for record in records {
                if record.logical_pk != *logical_pk
                    || record.expires_at <= now_ms
                    || record.auth_rank > rank
                {
                    continue;
                }

                // Check if the issuer itself was revoked BEFORE or AT this rank.
                if let Some(issuer_rev_rank) = self
                    .revoked_devices
                    .get(&(conversation_id, record.issuer_pk))
                    && *issuer_rev_rank <= rank
                {
                    continue;
                }

                // If it's a Level 1 device (issued by Master), its permissions are direct.
                if record.issuer_pk == logical_pk.to_physical() {
                    effective_perms = Some(
                        effective_perms
                            .map_or(record.permissions, |union| union | record.permissions),
                    );
                    continue;
                }

                // Otherwise, recursively check the issuer's permissions and intersect.
                if let Some(issuer_perms) = self.get_permissions_recursive(
                    conversation_id,
                    &record.issuer_pk,
                    logical_pk,
                    now_ms,
                    rank,
                    depth + 1,
                ) {
                    let path_perms = record.permissions & issuer_perms;
                    effective_perms =
                        Some(effective_perms.map_or(path_perms, |union| union | path_perms));
                    tracing::trace!(
                        "Path for {:?} via {:?}: cert={:?}, issuer={:?} -> path_effective={:?}",
                        device_pk,
                        record.issuer_pk,
                        record.permissions,
                        issuer_perms,
                        path_perms
                    );
                }
            }
            return effective_perms;
        }
        None
    }

    /// Returns a list of all authorized device PKs for a conversation, sorted for determinism.
    pub fn list_authorized_devices(
        &self,
        conversation_id: ConversationId,
    ) -> Vec<PhysicalDevicePk> {
        let mut pks: Vec<_> = self
            .authorized_devices
            .iter()
            .filter(|((cid, _), _)| cid == &conversation_id)
            .map(|((_, pk), _)| *pk)
            .collect();
        pks.sort_unstable();
        pks
    }

    /// Returns a list of all authorized device PKs for a conversation that are NOT revoked at the given rank/time.
    pub fn list_active_authorized_devices(
        &mut self,
        conversation_id: ConversationId,
        now_ms: i64,
        rank: u64,
    ) -> Vec<PhysicalDevicePk> {
        let members = self.list_members(conversation_id);
        let mut active_devices = Vec::new();

        // Get all device candidates for this conversation
        let candidates: Vec<PhysicalDevicePk> = self
            .authorized_devices
            .keys()
            .filter(|(cid, _)| cid == &conversation_id)
            .map(|(_, pk)| *pk)
            .collect();

        for device_pk in candidates {
            for (logical_pk, _, _) in &members {
                if self.is_authorized(conversation_id, &device_pk, logical_pk, now_ms, rank) {
                    active_devices.push(device_pk);
                    break;
                }
            }
        }

        active_devices.sort_unstable();
        active_devices.dedup();
        active_devices
    }

    /// Resolves a physical Device PK to its Logical PK (Master PK) for a specific conversation.
    pub fn resolve_logical_pk(
        &self,
        conversation_id: ConversationId,
        device_pk: &PhysicalDevicePk,
    ) -> Option<LogicalIdentityPk> {
        if let Some((_, _)) = self
            .logical_members
            .get(&(conversation_id, device_pk.to_logical()))
        {
            return Some(device_pk.to_logical());
        }
        self.authorized_devices
            .get(&(conversation_id, *device_pk))
            .and_then(|records| records.first().map(|r| r.logical_pk))
    }

    pub fn is_admin(
        &self,
        conversation_id: ConversationId,
        device_pk: &PhysicalDevicePk,
        logical_pk: &LogicalIdentityPk,
        now_ms: i64,
        rank: u64,
    ) -> bool {
        self.get_permissions(conversation_id, device_pk, logical_pk, now_ms, rank)
            .is_some_and(|p| p.contains(Permissions::ADMIN))
    }
}
