use generic_ec::{Curve, Point, Scalar};

use rand_core::RngCore;
use sha2::{Digest, Sha256};

#[derive(Debug, PartialEq)]
pub enum CryptoError {
    DecodeError,
    InvalidLength,
}

pub fn encrypt<E: Curve>(
    pk: &Point<E>,
    m: &[u8],
    rng: &mut impl RngCore,
) -> Result<Vec<u8>, CryptoError> {
    //While scalar works for now, can take a look at using SecretScalar as well, but that will need a secure rng implementation, something like CryptoRng
    let eph = Scalar::<E>::random(rng);
    
    let r = Point::<E>::generator() * &eph;
    
    let shared_secret = pk * &eph;
    let shared_bytes = shared_secret.to_bytes(true);
    
    let k_hash = Sha256::digest(shared_bytes.as_ref());

    let k_iter = k_hash.iter().cycle();

    let mut res = r.to_bytes(true).as_ref().to_vec();

    res.extend(m.iter().zip(k_iter).map(|(&mi, &ki)| mi ^ ki));
    
    Ok(res)
}


pub fn decrypt<E: Curve>(sk: &Scalar<E>, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let r_len = Point::<E>::zero().to_bytes(true).as_ref().len();
    
    if ciphertext.len() < r_len {
        return Err(CryptoError::InvalidLength);
    }

    let (r_bytes, c) = ciphertext.split_at(r_len);
    let r = Point::<E>::from_bytes(r_bytes).map_err(|_| CryptoError::DecodeError)?;
    
    let shared_secret = r * sk;
    let shared_bytes = shared_secret.to_bytes(true);
    
    let k_hash = Sha256::digest(shared_bytes.as_ref());
    let k_iter = k_hash.iter().cycle();

    Ok(c.iter().zip(k_iter).map(|(&ci, &ki)| ci ^ ki).collect())
}