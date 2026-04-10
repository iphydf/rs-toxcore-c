pub const CREATE_TABLES: &str = "
    CREATE TABLE IF NOT EXISTS nodes (
        hash BLOB PRIMARY KEY,
        conversation_id BLOB NOT NULL,
        node_type INTEGER NOT NULL,
        author_pk BLOB NOT NULL,
        sender_pk BLOB NOT NULL,
        network_timestamp INTEGER NOT NULL,
        sequence_number INTEGER NOT NULL,
        topological_rank INTEGER NOT NULL,
        admin_distance INTEGER NOT NULL DEFAULT 0,
        parents BLOB NOT NULL,
        verification_status INTEGER NOT NULL,
        raw_data BLOB NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_nodes_conv ON nodes(conversation_id);

    CREATE TABLE IF NOT EXISTS edges (
        parent_hash BLOB NOT NULL,
        child_hash BLOB NOT NULL,
        PRIMARY KEY (parent_hash, child_hash)
    );

    CREATE INDEX IF NOT EXISTS idx_edges_child ON edges(child_hash);

    CREATE TABLE IF NOT EXISTS global_state (
        key TEXT PRIMARY KEY,
        value BLOB
    );

    CREATE TABLE IF NOT EXISTS conversation_meta (
        conversation_id BLOB PRIMARY KEY,
        last_sync_time INTEGER,
        title_cache TEXT,
        heads BLOB,
        admin_heads BLOB,
        message_count INTEGER DEFAULT 0,
        last_rotation_time INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS conversation_keys (
        conversation_id BLOB NOT NULL,
        epoch INTEGER NOT NULL,
        k_conv BLOB NOT NULL,
        PRIMARY KEY (conversation_id, epoch)
    );

    CREATE TABLE IF NOT EXISTS cas_blobs (
        hash BLOB PRIMARY KEY,
        data BLOB,
        file_path TEXT,
        status TEXT NOT NULL,
        total_size INTEGER NOT NULL,
        received_chunks BLOB
    );

    CREATE TABLE IF NOT EXISTS reconciliation_sketches (
        conversation_id BLOB NOT NULL,
        min_rank INTEGER NOT NULL,
        max_rank INTEGER NOT NULL,
        sketch BLOB NOT NULL,
        PRIMARY KEY (conversation_id, min_rank, max_rank)
    );

    CREATE TABLE IF NOT EXISTS ratchet_keys (
        conversation_id BLOB NOT NULL,
        node_hash BLOB NOT NULL,
        chain_key BLOB NOT NULL,
        epoch_id INTEGER NOT NULL,
        PRIMARY KEY (conversation_id, node_hash)
    );

    CREATE TABLE IF NOT EXISTS opaque_nodes (
        hash BLOB PRIMARY KEY,
        conversation_id BLOB NOT NULL,
        raw_data BLOB NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_opaque_nodes_conv ON opaque_nodes(conversation_id);
";
