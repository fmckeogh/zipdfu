//! The iteration order of CPython `set`s of integers.
//!
//! nrfutil de-duplicates the SoftDevice IDs of an init packet with `list(set(ids))`, so their order
//! in its packages is CPython's hash table order rather than the command line order. Bootloaders
//! treat the list as unordered; reproducing the order only serves to make packages byte-for-byte
//! identical to nrfutil's.

/// Returns the distinct `values` in the order CPython iterates `set(values)`.
///
/// This follows `set_add_entry()` and `set_table_resize()` in CPython's `Objects/setobject.c`,
/// using that the hash of a small non-negative `int` is the value itself. The behaviour is the
/// same in CPython 3.7 to 3.14 at least.
pub fn set_order(values: &[u32]) -> Vec<u32> {
    const MIN_SIZE: usize = 8;

    let mut table = vec![None; MIN_SIZE];
    let mut used = 0;
    for &value in values {
        if !insert(&mut table, value) {
            continue;
        }
        used += 1;
        // Grow once the table is 60% full, to the smallest power of two above `used * 4`.
        if used * 5 >= (table.len() - 1) * 3 {
            let min_used = if used > 50_000 { used * 2 } else { used * 4 };
            let mut size = MIN_SIZE;
            while size <= min_used {
                size <<= 1;
            }
            let old = std::mem::replace(&mut table, vec![None; size]);
            for value in old.into_iter().flatten() {
                insert(&mut table, value);
            }
        }
    }
    table.into_iter().flatten().collect()
}

/// Inserts `value` using CPython's probe sequence. Returns false if it was already present.
fn insert(table: &mut [Option<u32>], value: u32) -> bool {
    const LINEAR_PROBES: usize = 9;
    const PERTURB_SHIFT: u32 = 5;

    let mask = table.len() - 1;
    let mut perturb = value as usize;
    let mut i = value as usize & mask;
    loop {
        let probes = if i + LINEAR_PROBES <= mask {
            LINEAR_PROBES
        } else {
            0
        };
        for slot in &mut table[i..=i + probes] {
            match *slot {
                None => {
                    *slot = Some(value);
                    return true;
                }
                Some(existing) if existing == value => return false,
                Some(_) => {}
            }
        }
        perturb >>= PERTURB_SHIFT;
        i = i.wrapping_mul(5).wrapping_add(1).wrapping_add(perturb) & mask;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(list: &str) -> Vec<u32> {
        list.split(',').map(|n| n.trim().parse().unwrap()).collect()
    }

    #[test]
    fn matches_cpython() {
        let vectors = include_str!("../tests/fixtures/cpython_set_order.txt");
        let mut count = 0;
        for line in vectors.lines().filter(|l| !l.starts_with('#')) {
            let (input, expected) = line.split_once(" => ").unwrap();
            assert_eq!(set_order(&parse(input)), parse(expected), "set({input})");
            count += 1;
        }
        assert_eq!(count, 75);
    }

    #[test]
    fn typical_softdevice_ids() {
        // `--sd-req 0xB6 --sd-id 0xCA` makes nrfutil require [0xCA, 0xB6] for the SoftDevice.
        assert_eq!(set_order(&[0xB6, 0xCA]), [0xCA, 0xB6]);
        assert_eq!(set_order(&[0xB6, 0xB6]), [0xB6]);
    }
}
