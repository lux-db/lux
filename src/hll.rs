pub const HLL_REGISTERS: usize = 16384;
const HLL_P: u32 = 14;

pub(crate) fn read_registers(
    reader: &mut impl std::io::Read,
    len: usize,
) -> std::io::Result<Vec<u8>> {
    if len != HLL_REGISTERS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid HyperLogLog register count",
        ));
    }
    let mut registers = vec![0; HLL_REGISTERS];
    reader.read_exact(&mut registers)?;
    if registers
        .iter()
        .any(|&value| value > (64 - HLL_P + 1) as u8)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid HyperLogLog register value",
        ));
    }
    Ok(registers)
}

pub fn murmur_hash_64a(data: &[u8]) -> u64 {
    let seed: u64 = 0xadc83b19;
    let m: u64 = 0xc6a4a7935bd1e995;
    let r: u32 = 47;
    let len = data.len();
    let mut h: u64 = seed ^ ((len as u64).wrapping_mul(m));

    let n_blocks = len / 8;
    for i in 0..n_blocks {
        let off = i * 8;
        let mut k = u64::from_le_bytes([
            data[off],
            data[off + 1],
            data[off + 2],
            data[off + 3],
            data[off + 4],
            data[off + 5],
            data[off + 6],
            data[off + 7],
        ]);

        k = k.wrapping_mul(m);
        k ^= k >> r;
        k = k.wrapping_mul(m);

        h ^= k;
        h = h.wrapping_mul(m);
    }

    let tail = &data[n_blocks * 8..];
    let remaining = tail.len();
    if remaining >= 7 {
        h ^= (tail[6] as u64) << 48;
    }
    if remaining >= 6 {
        h ^= (tail[5] as u64) << 40;
    }
    if remaining >= 5 {
        h ^= (tail[4] as u64) << 32;
    }
    if remaining >= 4 {
        h ^= (tail[3] as u64) << 24;
    }
    if remaining >= 3 {
        h ^= (tail[2] as u64) << 16;
    }
    if remaining >= 2 {
        h ^= (tail[1] as u64) << 8;
    }
    if remaining >= 1 {
        h ^= tail[0] as u64;
        h = h.wrapping_mul(m);
    }

    h ^= h >> r;
    h = h.wrapping_mul(m);
    h ^= h >> r;
    h
}

pub fn hll_add(registers: &mut [u8], element: &[u8]) -> bool {
    let hash = murmur_hash_64a(element);
    let index = (hash & ((1 << HLL_P) - 1)) as usize;
    let bits = hash >> HLL_P;
    let count = if bits == 0 {
        (64 - HLL_P) as u8 + 1
    } else {
        (bits.trailing_zeros() + 1) as u8
    };
    if count > registers[index] {
        registers[index] = count;
        true
    } else {
        false
    }
}

pub fn hll_count(registers: &[u8]) -> u64 {
    let m = HLL_REGISTERS as f64;
    let alpha = match HLL_REGISTERS {
        16 => 0.673,
        32 => 0.697,
        64 => 0.709,
        _ => 0.7213 / (1.0 + 1.079 / m),
    };

    let mut sum: f64 = 0.0;
    let mut zeros: u32 = 0;
    for &reg in registers.iter() {
        sum += 2.0_f64.powi(-(reg as i32));
        if reg == 0 {
            zeros += 1;
        }
    }

    let estimate = alpha * m * m / sum;

    if estimate <= 2.5 * m && zeros > 0 {
        (m * (m / zeros as f64).ln()).round() as u64
    } else {
        estimate.round() as u64
    }
}

pub fn hll_merge(dest: &mut [u8], src: &[u8]) {
    for i in 0..HLL_REGISTERS {
        if src[i] > dest[i] {
            dest[i] = src[i];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_registers_validate_shape_values_and_completeness() {
        for len in [
            0,
            1,
            HLL_REGISTERS - 1,
            HLL_REGISTERS + 1,
            u32::MAX as usize,
        ] {
            assert_eq!(
                read_registers(&mut &[][..], len).unwrap_err().kind(),
                std::io::ErrorKind::InvalidData
            );
        }
        assert_eq!(
            read_registers(&mut &[][..], HLL_REGISTERS)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::UnexpectedEof
        );
        let mut data = vec![51; HLL_REGISTERS];
        assert_eq!(
            read_registers(&mut data.as_slice(), data.len()).unwrap(),
            data
        );
        data[HLL_REGISTERS - 1] = 52;
        assert_eq!(
            read_registers(&mut data.as_slice(), data.len())
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn known_hash_values() {
        let h = murmur_hash_64a(b"");
        assert_ne!(h, 0);
        let h1 = murmur_hash_64a(b"hello");
        let h2 = murmur_hash_64a(b"hello");
        assert_eq!(h1, h2);
        let h3 = murmur_hash_64a(b"world");
        assert_ne!(h1, h3);
    }

    #[test]
    fn empty_count_is_zero() {
        let registers = vec![0u8; HLL_REGISTERS];
        assert_eq!(hll_count(&registers), 0);
    }

    #[test]
    fn add_count_roundtrip() {
        let mut registers = vec![0u8; HLL_REGISTERS];
        let n = 1000;
        for i in 0..n {
            let elem = format!("element:{}", i);
            hll_add(&mut registers, elem.as_bytes());
        }
        let count = hll_count(&registers);
        let error = (count as f64 - n as f64).abs() / n as f64;
        assert!(
            error < 0.05,
            "count {count} too far from {n}, error={error}"
        );
    }

    #[test]
    fn duplicate_detection() {
        let mut registers = vec![0u8; HLL_REGISTERS];
        let changed1 = hll_add(&mut registers, b"foo");
        assert!(changed1);
        let changed2 = hll_add(&mut registers, b"foo");
        assert!(!changed2);
    }

    #[test]
    fn merge_correctness() {
        let mut regs_a = vec![0u8; HLL_REGISTERS];
        let mut regs_b = vec![0u8; HLL_REGISTERS];

        for i in 0..500 {
            hll_add(&mut regs_a, format!("a:{}", i).as_bytes());
        }
        for i in 0..500 {
            hll_add(&mut regs_b, format!("b:{}", i).as_bytes());
        }

        let mut merged = vec![0u8; HLL_REGISTERS];
        hll_merge(&mut merged, &regs_a);
        hll_merge(&mut merged, &regs_b);

        let count = hll_count(&merged);
        let error = (count as f64 - 1000.0).abs() / 1000.0;
        assert!(
            error < 0.05,
            "merged count {count} too far from 1000, error={error}"
        );
    }

    #[test]
    fn accuracy_at_scale() {
        let mut registers = vec![0u8; HLL_REGISTERS];
        let n = 100_000;
        for i in 0..n {
            hll_add(&mut registers, format!("item:{}", i).as_bytes());
        }
        let count = hll_count(&registers);
        let error = (count as f64 - n as f64).abs() / n as f64;
        assert!(
            error < 0.02,
            "count {count} too far from {n}, error={error}"
        );
    }
}
