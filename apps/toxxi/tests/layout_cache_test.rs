use toxxi::widgets::{ChatLayout, ChatMessage, MessageContent, MessageStatus};

#[test]
fn test_lfu_cache_retention() {
    let mut layout = ChatLayout::default();

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

    // Use width A 5 times.
    for _ in 0..5 {
        layout.update(&messages, width_a);
    }

    // Use width B 5 times.
    for _ in 0..5 {
        layout.update(&messages, width_b);
    }

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

    // A resize drag: 15 widths, each used once. The cache holds 10.
    for i in 0..15 {
        let noise_width = 110 + i; // 110, 111, ..., 124
        layout.update(&messages, noise_width as u16);
    }

    // The frequently used widths stay.
    assert!(
        layout.cache.contains_key(&key_a),
        "LFU Cache evicted frequent Width A!"
    );
    assert!(
        layout.cache.contains_key(&key_b),
        "LFU Cache evicted frequent Width B!"
    );

    // The cache is bounded.
    assert_eq!(layout.cache.len(), 10, "Cache size should be capped at 10");

    // Usage counts are kept.
    assert_eq!(layout.cache.get(&key_a).unwrap().usage_count, 5);
    assert_eq!(layout.cache.get(&key_b).unwrap().usage_count, 5);

    // The rest are the most recent noise widths, 117 to 124: all were used once, so LRU decides.

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
