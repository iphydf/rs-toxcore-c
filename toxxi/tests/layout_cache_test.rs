use toxxi::widgets::{ChatLayout, ChatMessage, MessageContent, MessageStatus};

#[test]
fn test_lfu_cache_retention() {
    let mut layout = ChatLayout::default();

    // Setup: Create some messages
    let messages: Vec<ChatMessage> = (0..10)
        .map(|i| ChatMessage {
            sender: "Me".to_string(), // Width 2 -> clamped to 5
            timestamp: "12:00".to_string(),
            unix_timestamp: 1000 + i as u64,
            content: MessageContent::Text("Some content".to_string()),
            status: MessageStatus::Delivered,
            is_me: true,
            highlighted: false,
        })
        .collect();

    // Overhead calculation:
    // wide_mode (>50): time(8) + status(2) + sender(5) + separator(3) = 18
    // wrap_width = width - 18 - 1 (padding) = width - 19

    let width_a = 100;
    let key_a = 100 - 19; // 81

    let width_b = 200;
    let key_b = 200 - 19; // 181

    // Step 1: Use Width A frequently (5 times)
    for _ in 0..5 {
        layout.update(&messages, width_a);
    }

    // Step 2: Use Width B frequently (5 times)
    for _ in 0..5 {
        layout.update(&messages, width_b);
    }

    // Verify initial state
    assert!(
        layout.cache.contains_key(&key_a),
        "Cache should contain Width A"
    );
    assert!(
        layout.cache.contains_key(&key_b),
        "Cache should contain Width B"
    );
    assert_eq!(layout.cache.get(&key_a).unwrap().usage_count, 5);
    assert_eq!(layout.cache.get(&key_b).unwrap().usage_count, 5);

    // Step 3: Simulate resize drag (Noise)
    // Add 15 distinct intermediate widths, each used once.
    // Cache limit is 10.
    // We already have 2 items.
    // Adding 8 items -> cache full (10 items).
    // Adding 9th item -> evict 1 (should be one of the intermediate ones with usage 1).
    // ...
    for i in 0..15 {
        let noise_width = 110 + i; // 110, 111, ..., 124
        layout.update(&messages, noise_width as u16);
    }

    // Verification

    // 1. Frequently used items must remain
    assert!(
        layout.cache.contains_key(&key_a),
        "LFU Cache evicted frequent Width A!"
    );
    assert!(
        layout.cache.contains_key(&key_b),
        "LFU Cache evicted frequent Width B!"
    );

    // 2. Cache size must be bounded
    assert_eq!(layout.cache.len(), 10, "Cache size should be capped at 10");

    // 3. Verify usage counts are preserved
    assert_eq!(layout.cache.get(&key_a).unwrap().usage_count, 5);
    assert_eq!(layout.cache.get(&key_b).unwrap().usage_count, 5);

    // 4. Verify that the remaining items are the most recently used noise items
    // (Since noise items all have usage 1, LRU tie-breaking applies).
    // The loop added 110..124.
    // Last 8 items added should be in cache alongside A and B.
    // 124, 123, 122, 121, 120, 119, 118, 117.
    // 110..116 should have been evicted.

    let noise_start_evicted = 110 - 19;
    assert!(
        !layout.cache.contains_key(&(noise_start_evicted as u16)),
        "Oldest noise item should be evicted"
    );

    let noise_last_kept = 124 - 19;
    assert!(
        layout.cache.contains_key(&(noise_last_kept as u16)),
        "Newest noise item should be kept"
    );
}
