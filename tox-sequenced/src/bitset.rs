use tox_proto::ToxProto;

/// received fragments using a bitset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToxProto)]
#[tox(flat)]
pub struct BitSet<const N: usize> {
    words: [u64; N],
}

impl<const N: usize> Default for BitSet<N> {
    fn default() -> Self {
        Self { words: [0; N] }
    }
}

impl<const N: usize> BitSet<N> {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn get(&self, index: usize) -> bool {
        if index >= N * 64 {
            return false;
        }
        let word = index / 64;
        let bit = index % 64;
        (self.words[word] & (1 << bit)) != 0
    }

    #[inline]
    pub fn set(&mut self, index: usize) -> bool {
        if index >= N * 64 {
            return false;
        }
        let word = index / 64;
        let bit = index % 64;
        let mask = 1 << bit;
        if (self.words[word] & mask) == 0 {
            self.words[word] |= mask;
            true
        } else {
            false
        }
    }

    #[inline]
    pub fn unset(&mut self, index: usize) -> bool {
        if index >= N * 64 {
            return false;
        }
        let word = index / 64;
        let bit = index % 64;
        let mask = 1 << bit;
        if (self.words[word] & mask) != 0 {
            self.words[word] &= !mask;
            true
        } else {
            false
        }
    }

    pub fn clear(&mut self) {
        self.words = [0; N];
    }

    pub fn fill(&mut self) {
        self.words = [!0u64; N];
    }

    /// Returns the index of the first zero bit, clamped to `limit`.
    /// Useful for calculating the cumulative ACK base index.
    pub fn first_zero(&self, limit: usize) -> usize {
        let mut base = 0;
        for &word in self.words.iter() {
            if word == !0u64 {
                base += 64;
            } else {
                let trailing = word.trailing_ones() as usize;
                return (base + trailing).min(limit);
            }
        }
        base.min(limit)
    }

    /// Returns the index of the first zero bit starting from `start`, clamped to `limit`.
    /// Returns None if all bits in range [start, limit) are set.
    pub fn next_zero(&self, start: usize, limit: usize) -> Option<usize> {
        let mut idx = start;
        while idx < limit {
            let word_idx = idx / 64;
            if word_idx >= N {
                return Some(idx);
            } // Implicit zeros

            let bit_idx = idx % 64;
            let word = self.words[word_idx];

            // Create mask for bits >= bit_idx
            // We want bits from bit_idx upwards.
            let mask = !((1u64 << bit_idx).wrapping_sub(1));

            // Zeros become ones
            let inverted = !word;
            let masked = inverted & mask;

            if masked != 0 {
                let trailing = masked.trailing_zeros(); // Index of first set bit (was zero)
                let found = word_idx * 64 + trailing as usize;
                if found < limit {
                    return Some(found);
                } else {
                    return None;
                }
            }

            idx = (word_idx + 1) * 64;
        }
        None
    }

    /// Returns the index of the first set bit starting from `start`, clamped to `limit`.
    pub fn next_one(&self, start: usize, limit: usize) -> Option<usize> {
        let mut idx = start;
        while idx < limit {
            let word_idx = idx / 64;
            if word_idx >= N {
                return None;
            }

            let bit_idx = idx % 64;
            let word = self.words[word_idx];
            let mask = !((1u64 << bit_idx).wrapping_sub(1));
            let masked = word & mask;

            if masked != 0 {
                let trailing = masked.trailing_zeros();
                let found = word_idx * 64 + trailing as usize;
                if found < limit {
                    return Some(found);
                } else {
                    return None;
                }
            }
            idx = (word_idx + 1) * 64;
        }
        None
    }

    /// Returns the next contiguous range of set bits [start, end) within [search_start, limit).
    pub fn next_range(&self, search_start: usize, limit: usize) -> Option<(u16, u16)> {
        let start = self.next_one(search_start, limit)?;
        let end = self.next_zero(start, limit).unwrap_or(limit);
        Some((start as u16, end as u16))
    }

    /// Returns the index of the highest set bit less than `limit`, or None.
    pub fn last_one(&self, limit: usize) -> Option<usize> {
        let limit = limit.min(N * 64);
        if limit == 0 {
            return None;
        }

        let last_idx = limit - 1;
        let mut word_idx = last_idx / 64;
        let bit_limit = (last_idx % 64) + 1; // Bits 0..bit_limit-1 are valid

        // Check partial last word
        if bit_limit < 64 {
            // Mask to keep only bits [0, bit_limit)
            let mask = (1u64 << bit_limit) - 1;
            let masked_word = self.words[word_idx] & mask;
            if masked_word != 0 {
                let leading = masked_word.leading_zeros();
                return Some(word_idx * 64 + (63 - leading) as usize);
            }
            if word_idx == 0 {
                return None;
            }
            word_idx -= 1;
        }

        // Check full words backwards
        loop {
            let word = self.words[word_idx];
            if word != 0 {
                let leading = word.leading_zeros();
                return Some(word_idx * 64 + (63 - leading) as usize);
            }
            if word_idx == 0 {
                break;
            }
            word_idx -= 1;
        }
        None
    }

    /// Generates a 64-bit SACK mask starting *after* `base_index`.
    /// Bit 0 corresponds to `base_index + 1`.
    pub fn sack_mask(&self, base_index: usize) -> u64 {
        let start = base_index + 1;
        let word_idx = start / 64;
        let bit_idx = start % 64;

        if word_idx >= N {
            return 0;
        }

        let mut mask = self.words[word_idx] >> bit_idx;

        if bit_idx > 0 && word_idx + 1 < N {
            mask |= self.words[word_idx + 1] << (64 - bit_idx);
        }
        mask
    }

    /// Returns the number of set bits in the range [start, end).
    pub fn count_ones_between(&self, start: usize, end: usize) -> usize {
        let end = end.min(N * 64);
        if start >= end {
            return 0;
        }

        let start_word = start / 64;
        let end_word = (end - 1) / 64;

        if start_word == end_word {
            let mask = (!0u64 << (start % 64)) & (!0u64 >> (63 - (end - 1) % 64));
            return (self.words[start_word] & mask).count_ones() as usize;
        }

        let mut count = 0;

        // First partial word
        let start_mask = !0u64 << (start % 64);
        count += (self.words[start_word] & start_mask).count_ones() as usize;

        // Middle full words
        for i in (start_word + 1)..end_word {
            count += self.words[i].count_ones() as usize;
        }

        // Last partial word
        let end_mask = !0u64 >> (63 - (end - 1) % 64);
        count += (self.words[end_word] & end_mask).count_ones() as usize;

        count
    }
}
