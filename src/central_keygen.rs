use crate::THRESHOLD;
// use std::convert::TryFrom;
use crate::execute::execute_protocol;
use crate::tofn_common::keygen::initialize_honest_parties;
use crate::SecretKeyTemp;
use ecdsa::{elliptic_curve::sec1::FromEncodedPoint, hazmat::VerifyPrimitive};
use tofn::gg20::keygen::KeygenPartyId;
use tofn::gg20::keygen::KeygenProtocol;
#[cfg(feature = "malicious")]
use tofn::gg20::sign;
use tofn::gg20::sign::{new_sign, MessageDigest, SignParties, SignShareId};
use tofn::{
    collections::{TypedUsize, VecMap},
    gg20::keygen::{KeygenShareId, SecretKeyShare},
    sdk::api::{PartyShareCounts, Protocol},
};

use rand::Rng;
use tracing::debug;

pub(crate) fn call_vss_with_secret_key(n: usize, t: usize,secret_key: k256::Scalar) {
    // let Vss = tofn::


}
// pub(crate) fn initialize_centralized_parties(party_share_counts: &PartyShareCounts<KeygenPartyId>, threshold
// pub(crate) fn centralized_keygen(
//     party_share_counts: &PartyShareCounts<KeygenPartyId>,
//     threshold: usize,
// ) -> VecMap<KeygenShareId, KeygenProtocol> {
//     let protocol = Protocol::Done(Ok(SecretKeyShare {
//         group: GroupPublicInfo {
//             party_share_counts,
//             threshold: THRESHOLD,
//             y,
//             all_shares: v,
//         },
//         share: ShareSecretInfo {},
//     }));
// }
// pub(crate) fn central_keygen(
//     party_share_counts: &PartyShareCounts<KeygenPartyId>,
//     threshold: usize,
//     secret_key: SecretKeyTemp,
// ) {
//     let mut rng = rand::thread_rng();
//     let coefficients: Vec<usize> = std::iter::repeat_with(|| rng.gen())
//         .take(threshold)
//         .collect();

//     let secret_share_polynomial = |z: usize| -> usize {
//         coefficients
//             .iter()
//             .enumerate()
//             .map(|(i, a_i)| a_i * z.pow((i + 1) as u32))
//             .sum()
//     };

//     // let v = VecMap::from_iter((1..=party_share_counts.total_share_count()).map(secret_share_polynomial));
// }
