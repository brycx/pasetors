use crate::errors::Error;
use alloc::vec::Vec;
use core::convert::TryInto;

/// Encode `n` to little-endian bytes. The MSB is cleared.
pub fn le64(n: u64) -> [u8; core::mem::size_of::<u64>()] {
    let mut out = [0u8; core::mem::size_of::<u64>()];
    let mut n_tmp = n;

    out[0] = (n_tmp & 255) as u8;
    n_tmp >>= 8;
    out[1] = (n_tmp & 255) as u8;
    n_tmp >>= 8;
    out[2] = (n_tmp & 255) as u8;
    n_tmp >>= 8;
    out[3] = (n_tmp & 255) as u8;
    n_tmp >>= 8;
    out[4] = (n_tmp & 255) as u8;
    n_tmp >>= 8;
    out[5] = (n_tmp & 255) as u8;
    n_tmp >>= 8;
    out[6] = (n_tmp & 255) as u8;
    n_tmp >>= 8;
    n_tmp &= 127; // Clear the MSB for interoperability
    out[7] = (n_tmp & 255) as u8;

    out
}

/// Pre-Authentication Encoding. See [specification](https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Common.md#pae-definition).
pub fn pae(pieces: &[&[u8]]) -> Result<Vec<u8>, Error> {
    let mut out: Vec<u8> = Vec::with_capacity(64);

    out.extend_from_slice(&le64(pieces.len().try_into()?));
    for elem in pieces.iter() {
        out.extend_from_slice(&le64(elem.len().try_into()?));
        out.extend_from_slice(elem);
    }

    Ok(out)
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_le64() {
        assert_eq!(vec![0, 0, 0, 0, 0, 0, 0, 0], le64(0));
        assert_eq!(vec![10, 0, 0, 0, 0, 0, 0, 0], le64(10));
    }

    #[test]
    fn test_pae() {
        // Source: https://github.com/paragonie/paseto/blob/master/tests/UtilTest.php
        assert_eq!("0000000000000000", hex::encode(pae(&[]).unwrap()));
        assert_eq!(
            "01000000000000000000000000000000",
            hex::encode(pae(&[b""]).unwrap())
        );
        assert_eq!(
            "020000000000000000000000000000000000000000000000",
            hex::encode(pae(&[b"", b""]).unwrap())
        );
        assert_eq!(
            "0100000000000000070000000000000050617261676f6e",
            hex::encode(pae(&[b"Paragon"]).unwrap())
        );
        assert_eq!(
            "0200000000000000070000000000000050617261676f6e0a00000000000000496e6974696174697665",
            hex::encode(pae(&[b"Paragon", b"Initiative",]).unwrap())
        );
        assert_eq!(
            "0100000000000000190000000000000050617261676f6e0a00000000000000496e6974696174697665",
            hex::encode(pae(&[b"Paragon\n\0\0\0\0\0\0\0Initiative"]).unwrap())
        );
    }
}
