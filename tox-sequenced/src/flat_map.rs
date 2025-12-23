use std::borrow::Borrow;
use std::mem;
use std::{slice, vec};

use tox_proto::ToxProto;

/// A simple associative map implemented as a flat vector of key-value pairs.
///
/// `FlatMap` is optimized for small numbers of entries (typically N < 64). For small N,
/// a linear scan is often faster than hashing (`HashMap`) or tree traversal (`BTreeMap`)
/// due to better CPU cache locality and lower constant overhead.
///
/// In the context of `tox-sequenced`, it is used to track concurrent outgoing and
/// incoming messages, which are capped at 32 by the protocol.
#[derive(Debug, Clone, PartialEq, Eq, ToxProto)]
#[tox(flat)]
pub struct FlatMap<K, V> {
    data: Vec<(K, V)>,
}

impl<K, V> Default for FlatMap<K, V> {
    fn default() -> Self {
        Self { data: Vec::new() }
    }
}

impl<K, V> FlatMap<K, V> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn clear(&mut self) {
        self.data.clear();
    }

    pub fn iter(&self) -> slice::Iter<'_, (K, V)> {
        self.data.iter()
    }

    pub fn iter_mut(&mut self) -> slice::IterMut<'_, (K, V)> {
        self.data.iter_mut()
    }

    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.data.iter().map(|(_, v)| v)
    }

    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.data.iter().map(|(k, _)| k)
    }

    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&K, &mut V) -> bool,
    {
        self.data.retain_mut(|(k, v)| f(k, v));
    }
}

impl<K: Eq, V> FlatMap<K, V> {
    pub fn get<Q: ?Sized + Eq>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
    {
        self.data
            .iter()
            .find(|(k, _)| k.borrow() == key)
            .map(|(_, v)| v)
    }

    pub fn get_mut<Q: ?Sized + Eq>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
    {
        self.data
            .iter_mut()
            .find(|(k, _)| k.borrow() == key)
            .map(|(_, v)| v)
    }

    pub fn contains_key<Q: ?Sized + Eq>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
    {
        self.data.iter().any(|(k, _)| k.borrow() == key)
    }

    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        if let Some((_, v)) = self.data.iter_mut().find(|(k, _)| k == &key) {
            Some(mem::replace(v, value))
        } else {
            self.data.push((key, value));
            None
        }
    }

    pub fn remove<Q: ?Sized + Eq>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
    {
        if let Some(idx) = self.data.iter().position(|(k, _)| k.borrow() == key) {
            Some(self.data.remove(idx).1)
        } else {
            None
        }
    }

    pub fn entry(&mut self, key: K) -> Entry<'_, K, V> {
        if let Some(idx) = self.data.iter().position(|(k, _)| k == &key) {
            Entry::Occupied(OccupiedEntry {
                map: self,
                index: idx,
            })
        } else {
            Entry::Vacant(VacantEntry { map: self, key })
        }
    }
}

pub enum Entry<'a, K, V> {
    Occupied(OccupiedEntry<'a, K, V>),
    Vacant(VacantEntry<'a, K, V>),
}

impl<'a, K, V> Entry<'a, K, V> {
    pub fn or_insert(self, default: V) -> &'a mut V {
        match self {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(default),
        }
    }
}

pub struct OccupiedEntry<'a, K, V> {
    map: &'a mut FlatMap<K, V>,
    index: usize,
}

impl<'a, K, V> OccupiedEntry<'a, K, V> {
    pub fn into_mut(self) -> &'a mut V {
        &mut self.map.data[self.index].1
    }

    pub fn get(&self) -> &V {
        &self.map.data[self.index].1
    }

    pub fn get_mut(&mut self) -> &mut V {
        &mut self.map.data[self.index].1
    }
}

pub struct VacantEntry<'a, K, V> {
    map: &'a mut FlatMap<K, V>,
    key: K,
}

impl<'a, K, V> VacantEntry<'a, K, V> {
    pub fn insert(self, value: V) -> &'a mut V {
        self.map.data.push((self.key, value));
        &mut self.map.data.last_mut().unwrap().1
    }
}

impl<K, V> IntoIterator for FlatMap<K, V> {
    type Item = (K, V);
    type IntoIter = vec::IntoIter<(K, V)>;

    fn into_iter(self) -> Self::IntoIter {
        self.data.into_iter()
    }
}

impl<'a, K, V> IntoIterator for &'a FlatMap<K, V> {
    type Item = &'a (K, V);
    type IntoIter = slice::Iter<'a, (K, V)>;

    fn into_iter(self) -> Self::IntoIter {
        self.data.iter()
    }
}

impl<'a, K, V> IntoIterator for &'a mut FlatMap<K, V> {
    type Item = &'a mut (K, V);
    type IntoIter = slice::IterMut<'a, (K, V)>;

    fn into_iter(self) -> Self::IntoIter {
        self.data.iter_mut()
    }
}

impl<K, V> FromIterator<(K, V)> for FlatMap<K, V>
where
    K: Eq,
{
    fn from_iter<T: IntoIterator<Item = (K, V)>>(iter: T) -> Self {
        let mut map = FlatMap::new();
        for (k, v) in iter {
            map.insert(k, v);
        }
        map
    }
}
