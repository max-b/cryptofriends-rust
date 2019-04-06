pub mod challenge_41;
pub mod challenge_42;
pub mod challenge_43;
pub mod challenge_44;
pub mod challenge_45;
pub mod challenge_46;
// pub mod challenge_47;

use bigint::BigUint;
use num_traits::ops::checked::CheckedSub;
use utils::crypto::dsa::{DsaParams, DsaSignature};
use utils::bigint;

pub fn recover_dsa_private_key_from_signing_key(
    params: &DsaParams,
    signature: &DsaSignature,
    k: &BigUint,
) -> Option<BigUint> {
    let (_, inv_r) = bigint::euclidean_algorithm(&params.q, &signature.r);
    let sk = &signature.s * k;
    match sk.checked_sub(&signature.message_hash) {
        Some(t) => Some(((t % &params.q) * &inv_r) % &params.q),
        None => None,
    }
}
