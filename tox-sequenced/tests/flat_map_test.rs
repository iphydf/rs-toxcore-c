use tox_sequenced::flat_map::FlatMap;

#[test]
fn test_flat_map_basic_ops() {
    let mut map = FlatMap::new();
    assert!(map.is_empty());

    assert_eq!(map.insert(1, "one"), None);
    assert_eq!(map.len(), 1);
    assert!(!map.is_empty());

    assert_eq!(map.get(&1), Some(&"one"));
    assert_eq!(map.insert(1, "ONE"), Some("one"));
    assert_eq!(map.get(&1), Some(&"ONE"));

    assert_eq!(map.insert(2, "two"), None);
    assert_eq!(map.len(), 2);

    assert_eq!(map.remove(&1), Some("ONE"));
    assert_eq!(map.len(), 1);
    assert_eq!(map.get(&1), None);

    assert_eq!(map.remove(&1), None);
}

#[test]
fn test_flat_map_entry_api() {
    let mut map = FlatMap::new();

    map.entry(1).or_insert("one");
    assert_eq!(map.get(&1), Some(&"one"));

    map.entry(1).or_insert("uno");
    assert_eq!(map.get(&1), Some(&"one"));

    {
        let val = map.entry(2).or_insert("two");
        *val = "TWO";
    }
    assert_eq!(map.get(&2), Some(&"TWO"));
}

#[test]
fn test_flat_map_iteration() {
    let mut map = FlatMap::new();
    map.insert(1, "a");
    map.insert(2, "b");
    map.insert(3, "c");

    let keys: Vec<_> = map.keys().cloned().collect();
    assert_eq!(keys, vec![1, 2, 3]);

    let values: Vec<_> = map.values().cloned().collect();
    assert_eq!(values, vec!["a", "b", "c"]);

    for (k, v) in map.iter_mut() {
        if *k == 2 {
            *v = "B";
        }
    }
    assert_eq!(map.get(&2), Some(&"B"));

    let pairs: Vec<_> = map.into_iter().collect();
    assert_eq!(pairs, vec![(1, "a"), (2, "B"), (3, "c")]);
}

#[test]
fn test_flat_map_tox_proto() {
    let mut map = FlatMap::new();
    map.insert("key1".to_string(), 100);
    map.insert("key2".to_string(), 200);

    let serialized = tox_proto::serialize(&map).unwrap();

    let deserialized: FlatMap<String, i32> = tox_proto::deserialize(&serialized).unwrap();
    assert_eq!(deserialized.get("key1"), Some(&100));
    assert_eq!(deserialized.get("key2"), Some(&200));
    assert_eq!(deserialized.len(), 2);
}

#[test]
fn test_flat_map_from_iterator() {
    let pairs = vec![(1, "a"), (2, "b"), (3, "c")];
    let map: FlatMap<i32, &str> = pairs.into_iter().collect();

    assert_eq!(map.len(), 3);
    assert_eq!(map.get(&1), Some(&"a"));
    assert_eq!(map.get(&2), Some(&"b"));
    assert_eq!(map.get(&3), Some(&"c"));
}

#[test]
fn test_flat_map_entry_complex() {
    let mut map = FlatMap::<String, i32>::new();
    map.insert("a".to_string(), 1);

    // Test or_insert returning mutable reference
    {
        let v = map.entry("b".to_string()).or_insert(2);
        *v += 10;
    }
    assert_eq!(map.get("b"), Some(&12));

    // Test Occupied entry modification
    if let tox_sequenced::flat_map::Entry::Occupied(mut occ) = map.entry("a".to_string()) {
        *occ.get_mut() += 100;
    }
    assert_eq!(map.get("a"), Some(&101));
}

#[test]
fn test_flat_map_tox_proto_roundtrip() {
    let mut map = FlatMap::<String, Vec<u8>>::new();
    map.insert("first".to_string(), vec![1, 2, 3]);
    map.insert("second".to_string(), vec![4, 5, 6]);

    let encoded = tox_proto::serialize(&map).expect("Failed to serialize");
    let decoded: FlatMap<String, Vec<u8>> =
        tox_proto::deserialize(&encoded).expect("Failed to deserialize");

    assert_eq!(decoded.len(), 2);
    assert_eq!(decoded.get("first"), Some(&vec![1, 2, 3]));
    assert_eq!(decoded.get("second"), Some(&vec![4, 5, 6]));
}

#[test]
fn test_flat_map_retain() {
    let mut map: FlatMap<i32, i32> = (0..10).map(|i| (i, i)).collect();
    map.retain(|k, _| k % 2 == 0);

    assert_eq!(map.len(), 5);
    for i in 0..10 {
        if i % 2 == 0 {
            assert!(map.contains_key(&i));
        } else {
            assert!(!map.contains_key(&i));
        }
    }
}

// end of tests
