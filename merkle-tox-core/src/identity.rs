use crate::dag::{
    ConversationId, DelegationCertificate, Ed25519Signature, LogicalIdentityPk, NodeHash,
    Permissions, PhysicalDevicePk,
};
use ed25519_dalek::{Signature as DalekSignature, Signer, SigningKey, Verifier, VerifyingKey};
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use tox_proto::ToxProto;
use tox_proto::constants::{MAX_AUTH_DEPTH, MAX_DEVICES_PER_IDENTITY};
use tracing::{debug, trace, warn};

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
    #[error("Too many devices for this identity (max {0})")]
    TooManyDevices(usize),
    #[error("Too many devices in group (max {0})")]
    TooManyGroupDevices(usize),
}

#[derive(ToxProto)]
pub struct DelegationSignData {
    pub device_pk: PhysicalDevicePk,
    pub permissions: Permissions,
    pub expires_at: i64,
    pub version: u32,
    pub conversation_id: ConversationId,
}

/// Current delegation certificate protocol version.
pub const DELEGATION_VERSION: u32 = 1;

/// Signs delegation certificate.
pub fn sign_delegation(
    signing_key: &SigningKey,
    device_pk: PhysicalDevicePk,
    permissions: Permissions,
    expires_at: i64,
    conversation_id: ConversationId,
) -> DelegationCertificate {
    let sign_data = DelegationSignData {
        device_pk,
        permissions,
        expires_at,
        version: DELEGATION_VERSION,
        conversation_id,
    };
    let signed_data = tox_proto::serialize(&sign_data).expect("Failed to serialize sign data");
    let signature = Ed25519Signature::from(signing_key.sign(&signed_data).to_bytes());

    DelegationCertificate {
        device_pk,
        permissions,
        expires_at,
        signature,
        version: DELEGATION_VERSION,
        conversation_id,
    }
}

/// Verifies delegation certificate against issuer's public key.
pub fn verify_delegation<P: AsRef<[u8; 32]>>(
    cert: &DelegationCertificate,
    issuer_pk: P,
    now_ms: i64,
) -> Result<(), IdentityError> {
    if cert.expires_at < now_ms {
        debug!("Cert expired: {} < {}", cert.expires_at, now_ms);
        return Err(IdentityError::Expired(cert.expires_at, now_ms));
    }

    let verifying_key = VerifyingKey::from_bytes(issuer_pk.as_ref())
        .map_err(|_| IdentityError::InvalidSignature)?;
    let signature = DalekSignature::from_bytes(cert.signature.as_ref());

    let sign_data = DelegationSignData {
        device_pk: cert.device_pk,
        permissions: cert.permissions,
        expires_at: cert.expires_at,
        version: cert.version,
        conversation_id: cert.conversation_id,
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
    pub issuer_pk: PhysicalDevicePk, // Used for master and devices
    pub permissions: Permissions,
    pub expires_at: i64,
    pub auth_rank: u64,
    pub auth_hash: NodeHash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationRecord {
    pub rank: u64,
    pub revoker_seniority: (u64, NodeHash),
    pub revocation_hash: NodeHash,
}

pub struct CausalContext {
    pub evaluating_node_hash: NodeHash,
    pub admin_ancestor_hashes: HashSet<NodeHash>,
}

impl CausalContext {
    /// Returns global causal context. Bypasses specific node-ancestry checks
    /// and should only be used for proactive self-checks (e.g., UI, background tasks)
    /// to determine active permissions across all DAG heads.
    pub fn global() -> Self {
        let mut admin_ancestor_hashes = HashSet::new();
        admin_ancestor_hashes.insert(NodeHash::from([0u8; 32]));
        Self {
            evaluating_node_hash: NodeHash::from([0u8; 32]),
            admin_ancestor_hashes,
        }
    }
}

/// Cache of verified trust paths from Physical Device PKs to Logical Identities.
pub struct IdentityManager {
    /// Mapping of (ConversationID, Device PK) to List of Authorization Records
    authorized_devices: HashMap<(ConversationId, PhysicalDevicePk), Vec<AuthRecord>>,
    /// Mapping of (ConversationID, Logical PK) to (Role, JoinedAt)
    logical_members: HashMap<(ConversationId, LogicalIdentityPk), (u8, i64)>,
    /// Mapping of (ConversationID, Revoked Device PK) to List of Revocation Records
    revoked_devices: HashMap<(ConversationId, PhysicalDevicePk), Vec<RevocationRecord>>,
    /// Cache of verified paths to avoid redundant recursive checks.
    /// (ConversationID, Device PK, Logical PK, EvaluatingNodeHash) -> min_expires_at
    path_cache: Mutex<
        lru::LruCache<
            (
                ConversationId,
                PhysicalDevicePk,
                LogicalIdentityPk,
                NodeHash,
            ),
            i64,
        >,
    >,
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
            path_cache: Mutex::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(1000).unwrap(),
            )),
        }
    }

    /// Returns true when devices MUTUALLY revoked each other (MAD scenario).
    /// The `(rank, auth_hash)` tuple tiebreaker selects survivor;
    /// one-sided revocations use simpler rank-only check.
    fn is_mutual_revocation(
        &self,
        conversation_id: ConversationId,
        revoker_auth_hash: NodeHash,
        target_auth_hash: NodeHash,
    ) -> bool {
        // Zero-hash means master-key or bootstrap revocation, not subject to MAD.
        if revoker_auth_hash == NodeHash::from([0u8; 32])
            || target_auth_hash == NodeHash::from([0u8; 32])
        {
            return false;
        }
        // Find device_pk owning revoker_auth_hash.
        let revoker_pk = self
            .authorized_devices
            .iter()
            .find_map(|((cid, pk), records)| {
                if *cid == conversation_id
                    && records.iter().any(|r| r.auth_hash == revoker_auth_hash)
                {
                    Some(*pk)
                } else {
                    None
                }
            });
        // Check whether device was revoked by target
        // (i.e., target's auth_hash appears as revoker in those records).
        revoker_pk.is_some_and(|rk| {
            self.revoked_devices
                .get(&(conversation_id, rk))
                .is_some_and(|revs| {
                    revs.iter()
                        .any(|r| r.revoker_seniority.1 == target_auth_hash)
                })
        })
    }

    /// Records logical member.
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

    /// Removes logical member at specific rank.
    #[allow(clippy::too_many_arguments)]
    pub fn remove_member(
        &mut self,
        conversation_id: ConversationId,
        revoker_pk: PhysicalDevicePk,
        revoker_logical_pk: LogicalIdentityPk,
        logical_pk: LogicalIdentityPk,
        rank: u64,
        now_ms: i64,
        revocation_hash: NodeHash,
    ) {
        self.logical_members.remove(&(conversation_id, logical_pk));
        // Also revoke their devices
        let devices_to_remove: Vec<_> = self
            .authorized_devices
            .iter()
            .filter(|((cid, _), records)| {
                cid == &conversation_id && records.iter().any(|r| r.logical_pk == logical_pk)
            })
            .map(|((_, d), _)| *d)
            .collect();
        for d in devices_to_remove {
            self.revoke_device(
                conversation_id,
                revoker_pk,
                revoker_logical_pk,
                d,
                rank,
                now_ms,
                revocation_hash,
            );
        }
    }

    /// Returns list of logical members for conversation, sorted by PK for determinism.
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

    /// Returns founder's LogicalIdentityPk for conversation.
    pub fn get_founder(&self, conversation_id: &ConversationId) -> Option<LogicalIdentityPk> {
        self.logical_members
            .iter()
            .find_map(|(&(cid, pk), &(role, _))| {
                if cid == *conversation_id && role == 0 {
                    Some(pk)
                } else {
                    None
                }
            })
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

    /// Revokes device at specific rank.
    #[allow(clippy::too_many_arguments)]
    pub fn revoke_device(
        &mut self,
        conversation_id: ConversationId,
        revoker_pk: PhysicalDevicePk,
        revoker_logical_pk: LogicalIdentityPk,
        target_device_pk: PhysicalDevicePk,
        rank: u64,
        now_ms: i64,
        revocation_hash: NodeHash,
    ) {
        let mut revoker_seniority = (u64::MAX, NodeHash::from([0xFF; 32]));

        if revoker_pk == revoker_logical_pk.to_physical() {
            revoker_seniority = (0, NodeHash::from([0u8; 32]));
        } else if let Some(records) = self.authorized_devices.get(&(conversation_id, revoker_pk)) {
            // Find oldest explicitly granted ADMIN record
            for record in records {
                if record.logical_pk == revoker_logical_pk
                    && record.expires_at > now_ms
                    && record.auth_rank <= rank
                    && record.permissions.contains(Permissions::ADMIN)
                {
                    let seniority = (record.auth_rank, record.auth_hash);
                    if seniority < revoker_seniority {
                        revoker_seniority = seniority;
                    }
                }
            }
        }

        let new_rec = RevocationRecord {
            rank,
            revoker_seniority,
            revocation_hash,
        };
        self.revoked_devices
            .entry((conversation_id, target_device_pk))
            .and_modify(|list| {
                list.push(new_rec.clone());
            })
            .or_insert_with(|| vec![new_rec]);

        self.path_cache.lock().clear(); // Clear cache on revocation
    }

    /// Authorizes device using delegation certificate at specific rank.
    /// Certificate issuer must be Logical Identity (Master Seed)
    /// or another authorized device with ADMIN permissions.
    #[allow(clippy::too_many_arguments)]
    pub fn authorize_device(
        &mut self,
        ctx: &CausalContext,
        conversation_id: ConversationId,
        logical_pk: LogicalIdentityPk,
        cert: &DelegationCertificate,
        now_ms: i64,
        rank: u64,
        auth_hash: NodeHash,
    ) -> Result<(), IdentityError> {
        self.path_cache.lock().clear(); // Clear cache on authorization

        // 1. Level 1 delegation if issuer is logical_pk (Master Seed).
        if let Err(e) = verify_delegation(cert, logical_pk, now_ms) {
            debug!("Level 1 auth failed for {:?}: {:?}", cert.device_pk, e);
        } else {
            debug!("Level 1 auth success for {:?}", cert.device_pk);
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
                auth_hash,
            };

            if !records.contains(&record) {
                records.push(record);
            }
            return Ok(());
        }

        // 2. Check if issuer is existing authorized ADMIN device.
        let mut issuer_pk = None;
        let mut issuer_perms = Permissions::NONE;
        tracing::debug!(
            "Checking Level 2+ auth for dev_pk={:?} at rank {}, candidates: {}",
            cert.device_pk,
            rank,
            self.authorized_devices.len()
        );

        // Find issuer and check effective permissions.
        for ((cid, dev_pk), records) in &self.authorized_devices {
            if cid != &conversation_id {
                continue;
            }

            for record in records {
                // Issuer must be authorized for correct logical identity
                // at rank <= current authorization node's rank.
                if record.logical_pk == logical_pk
                    && record.expires_at > now_ms
                    && record.auth_rank <= rank
                {
                    // Preliminary check for ADMIN permission in certificate record
                    // (Optimization: skip full recursive lookup if cert doesn't claim ADMIN)
                    if !record.permissions.contains(Permissions::ADMIN) {
                        trace!("Candidate issuer {:?} lacks ADMIN in cert", dev_pk);
                        continue;
                    }

                    if verify_delegation(cert, dev_pk, now_ms).is_ok() {
                        tracing::trace!(
                            "Candidate issuer {:?} signed the certificate, checking effective perms",
                            dev_pk
                        );
                        // Check effective permissions of issuer
                        if let Some(effective) = self.get_permissions_recursive(
                            ctx,
                            conversation_id,
                            dev_pk,
                            &logical_pk,
                            now_ms,
                            rank,
                            0,
                        ) {
                            if effective.contains(Permissions::ADMIN) {
                                debug!("Level 2+ auth success via issuer {:?}", dev_pk);
                                issuer_pk = Some(*dev_pk);
                                issuer_perms = effective;
                                break;
                            } else {
                                trace!(
                                    "Candidate issuer {:?} has NO effective ADMIN: {:?}",
                                    dev_pk, effective
                                );
                            }
                        } else {
                            trace!(
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
            // Device cannot delegate permissions it lacks.
            if !issuer_perms.contains(cert.permissions) {
                warn!(
                    "Device {:?} authorization REJECTED: escalation detected. Issuer {:?} has {:?}, tried to delegate {:?}",
                    cert.device_pk, issuer, issuer_perms, cert.permissions
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

            // Device Count Protection:
            // Count distinct devices authorized for this
            // logical identity in conversation.
            let device_count = self
                .authorized_devices
                .iter()
                .filter(|((cid, _), records)| {
                    *cid == conversation_id && records.iter().any(|r| r.logical_pk == logical_pk)
                })
                .count();
            if device_count >= MAX_DEVICES_PER_IDENTITY {
                return Err(IdentityError::TooManyDevices(MAX_DEVICES_PER_IDENTITY));
            }

            // Group-level device count protection (§ MAX_GROUP_DEVICES):
            let total_devices = self
                .authorized_devices
                .iter()
                .filter(|((cid, _), _)| *cid == conversation_id)
                .count();
            if total_devices >= tox_proto::constants::MAX_GROUP_DEVICES {
                return Err(IdentityError::TooManyGroupDevices(
                    tox_proto::constants::MAX_GROUP_DEVICES,
                ));
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
                auth_hash,
            };

            if !records.contains(&record) {
                records.push(record);
            }
            Ok(())
        } else {
            Err(IdentityError::NoTrustPath)
        }
    }

    /// Returns true if authorization record exists for device, regardless of validity.
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
        ctx: &CausalContext,
        conversation_id: ConversationId,
        device_pk: &PhysicalDevicePk,
        logical_pk: &LogicalIdentityPk,
        now_ms: i64,
        rank: u64,
    ) -> bool {
        if *device_pk == logical_pk.to_physical() {
            return true;
        }

        if let Some(&expires_at) = self.path_cache.lock().get(&(
            conversation_id,
            *device_pk,
            *logical_pk,
            ctx.evaluating_node_hash,
        )) && expires_at > now_ms
        {
            return true;
        }

        let res = self.is_authorized_recursive(
            ctx,
            conversation_id,
            device_pk,
            logical_pk,
            now_ms,
            rank,
            0,
        );
        if let Some(expires_at) = res {
            self.path_cache.lock().push(
                (
                    conversation_id,
                    *device_pk,
                    *logical_pk,
                    ctx.evaluating_node_hash,
                ),
                expires_at,
            );
            true
        } else {
            false
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn is_authorized_recursive(
        &self,
        ctx: &CausalContext,
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

        let revocations = self.revoked_devices.get(&(conversation_id, *device_pk));

        if let Some(records) = self.authorized_devices.get(&(conversation_id, *device_pk)) {
            let mut max_expires = None;

            for record in records {
                if record.logical_pk != *logical_pk
                    || record.expires_at <= now_ms
                    || record.auth_rank > rank
                {
                    continue;
                }

                if ctx.evaluating_node_hash != NodeHash::from([0u8; 32])
                    && record.auth_hash != NodeHash::from([0u8; 32])
                    && !ctx.admin_ancestor_hashes.contains(&record.auth_hash)
                {
                    continue;
                }

                let my_seniority = (record.auth_rank, record.auth_hash);
                let mut is_revoked = false;
                if let Some(revs) = revocations {
                    for rev in revs {
                        let in_history = rev.revocation_hash == NodeHash::from([0u8; 32])
                            || ctx.evaluating_node_hash == NodeHash::from([0u8; 32])
                            || ctx.admin_ancestor_hashes.contains(&rev.revocation_hash);
                        if in_history && rev.rank <= rank {
                            // For mutual (MAD) revocations use full (rank, hash) tuple so
                            // senior admin survives. One-sided revocations use
                            // simpler rank-only check so any admin can revoke at equal
                            // or lower seniority.
                            let is_mad = self.is_mutual_revocation(
                                conversation_id,
                                rev.revoker_seniority.1,
                                record.auth_hash,
                            );
                            let can_revoke = if is_mad {
                                rev.revoker_seniority <= my_seniority
                            } else {
                                rev.revoker_seniority.0 <= my_seniority.0
                            };
                            if can_revoke {
                                is_revoked = true;
                                break;
                            }
                        }
                    }
                }
                if is_revoked {
                    continue;
                }

                // Level 1 device (issued by Master) provides valid path.
                if record.issuer_pk == logical_pk.to_physical() {
                    max_expires = Some(
                        max_expires
                            .map_or(record.expires_at, |max: i64| max.max(record.expires_at)),
                    );
                    continue;
                }

                // Recursively check if issuer remains authorized.
                if let Some(issuer_expires) = self.is_authorized_recursive(
                    ctx,
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
        ctx: &CausalContext,
        conversation_id: ConversationId,
        device_pk: &PhysicalDevicePk,
        logical_pk: &LogicalIdentityPk,
        now_ms: i64,
        rank: u64,
    ) -> Option<Permissions> {
        let perms = self.get_permissions_recursive(
            ctx,
            conversation_id,
            device_pk,
            logical_pk,
            now_ms,
            rank,
            0,
        );
        tracing::trace!(
            "Permissions for {:?} in {:?}: {:?}",
            device_pk,
            conversation_id,
            perms
        );
        perms
    }

    #[allow(clippy::too_many_arguments)]
    fn get_permissions_recursive(
        &self,
        ctx: &CausalContext,
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

        let revocations = self.revoked_devices.get(&(conversation_id, *device_pk));

        if let Some(records) = self.authorized_devices.get(&(conversation_id, *device_pk)) {
            let mut effective_perms = None;

            for record in records {
                if record.logical_pk != *logical_pk
                    || record.expires_at <= now_ms
                    || record.auth_rank > rank
                {
                    trace!(
                        "Skipping record because logical_pk mismatch or expired or rank > auth_rank. log_pk: {}, expires: {}, now_ms: {}, auth_rank: {}, rank: {}",
                        record.logical_pk == *logical_pk,
                        record.expires_at <= now_ms,
                        now_ms,
                        record.auth_rank,
                        rank
                    );
                    continue;
                }

                if ctx.evaluating_node_hash != NodeHash::from([0u8; 32])
                    && record.auth_hash != NodeHash::from([0u8; 32])
                    && !ctx.admin_ancestor_hashes.contains(&record.auth_hash)
                {
                    trace!(
                        "Skipping record because auth_hash not in admin_ancestor_hashes! record.auth_hash: {:?}",
                        record.auth_hash
                    );
                    continue;
                }

                let my_seniority = (record.auth_rank, record.auth_hash);
                let mut is_revoked = false;
                if let Some(revs) = revocations {
                    for rev in revs {
                        let in_history = rev.revocation_hash == NodeHash::from([0u8; 32])
                            || ctx.evaluating_node_hash == NodeHash::from([0u8; 32])
                            || ctx.admin_ancestor_hashes.contains(&rev.revocation_hash);
                        if in_history && rev.rank <= rank {
                            let is_mad = self.is_mutual_revocation(
                                conversation_id,
                                rev.revoker_seniority.1,
                                record.auth_hash,
                            );
                            let can_revoke = if is_mad {
                                rev.revoker_seniority <= my_seniority
                            } else {
                                rev.revoker_seniority.0 <= my_seniority.0
                            };
                            if can_revoke {
                                is_revoked = true;
                                break;
                            }
                        }
                    }
                }
                if is_revoked {
                    continue;
                }

                // Level 1 device (issued by Master) has direct permissions.
                if record.issuer_pk == logical_pk.to_physical() {
                    effective_perms = Some(
                        effective_perms
                            .map_or(record.permissions, |union| union | record.permissions),
                    );
                    continue;
                }

                // Recursively check issuer's permissions and intersect.
                if let Some(issuer_perms) = self.get_permissions_recursive(
                    ctx,
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

    /// Returns list of authorized device PKs for conversation, sorted for determinism.
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

    /// Returns list of authorized device PKs for conversation NOT revoked at given rank/time.
    pub fn list_active_authorized_devices(
        &mut self,
        ctx: &CausalContext,
        conversation_id: ConversationId,
        now_ms: i64,
        rank: u64,
    ) -> Vec<PhysicalDevicePk> {
        let members = self.list_members(conversation_id);
        let mut active_devices = Vec::new();

        // Explicitly authorized device candidates from cert chains.
        let explicit_candidates: Vec<PhysicalDevicePk> = self
            .authorized_devices
            .keys()
            .filter(|(cid, _)| cid == &conversation_id)
            .map(|(_, pk)| *pk)
            .collect();

        // Check if explicit device is authorized for each logical member.
        // Otherwise include implicit device (logical_pk.to_physical())
        // authorized via is_authorized shortcut (identity-IS-the-device).
        for (logical_pk, _, _) in &members {
            let mut has_explicit_device = false;
            for &device_pk in &explicit_candidates {
                if self.is_authorized(ctx, conversation_id, &device_pk, logical_pk, now_ms, rank) {
                    active_devices.push(device_pk);
                    has_explicit_device = true;
                }
            }
            if !has_explicit_device {
                active_devices.push(logical_pk.to_physical());
            }
        }

        active_devices.sort_unstable();
        active_devices.dedup();
        active_devices
    }

    /// Resolves physical Device PK to Logical PK (Master PK) for conversation.
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
        ctx: &CausalContext,
        conversation_id: ConversationId,
        device_pk: &PhysicalDevicePk,
        logical_pk: &LogicalIdentityPk,
        now_ms: i64,
        rank: u64,
    ) -> bool {
        self.get_permissions(ctx, conversation_id, device_pk, logical_pk, now_ms, rank)
            .is_some_and(|p| p.contains(Permissions::ADMIN))
    }

    /// All (device, logical) pairs authorized in conversation.
    pub fn list_all_authorized_sender_pairs(
        &self,
        conversation_id: ConversationId,
    ) -> Vec<(PhysicalDevicePk, LogicalIdentityPk)> {
        let mut pairs = Vec::new();
        for ((cid, device_pk), records) in &self.authorized_devices {
            if *cid == conversation_id {
                for record in records {
                    pairs.push((*device_pk, record.logical_pk));
                }
            }
        }
        // Include logical members where device == logical.to_physical()
        for (cid, logical_pk) in self.logical_members.keys() {
            if *cid == conversation_id {
                let phys = logical_pk.to_physical();
                if !pairs.iter().any(|(d, l)| *d == phys && *l == *logical_pk) {
                    pairs.push((phys, *logical_pk));
                }
            }
        }
        pairs.sort_unstable();
        pairs.dedup();
        pairs
    }

    /// Returns list of authorized device PKs for logical identity in conversation.
    pub fn list_authorized_devices_for_author(
        &self,
        conversation_id: ConversationId,
        logical_pk: LogicalIdentityPk,
    ) -> Vec<PhysicalDevicePk> {
        let mut pks: Vec<_> = self
            .authorized_devices
            .iter()
            .filter(|((cid, _), records)| {
                cid == &conversation_id && records.iter().any(|r| r.logical_pk == logical_pk)
            })
            .map(|((_, pk), _)| *pk)
            .collect();
        // Always include author's own device PK (Level 0/1)
        if !pks.contains(&logical_pk.to_physical()) {
            pks.push(logical_pk.to_physical());
        }
        pks.sort_unstable();
        pks
    }
}
