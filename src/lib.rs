// use std::convert::TryFrom;
use crate::execute::execute_protocol;
use crate::tofn_common::keygen::initialize_honest_parties;
use ecdsa::{elliptic_curve::sec1::FromEncodedPoint, hazmat::VerifyPrimitive};
#[cfg(feature = "malicious")]
use tofn::gg20::sign;
use tofn::gg20::sign::{new_sign, MessageDigest, SignParties, SignShareId};
use tofn::{
    collections::{TypedUsize, VecMap},
    gg20::keygen::{KeygenShareId, SecretKeyShare},
    sdk::api::{PartyShareCounts, Protocol},
};
use tracing::debug;

fn set_up_logs() {
    // set up environment variable for log level
    // set up an event subscriber for logs
    let _ = tracing_subscriber::fmt()
        // .with_env_filter("tofnd=info,[Keygen]=info")
        .with_max_level(tracing::Level::DEBUG)
        // .json()
        // .with_ansi(atty::is(atty::Stream::Stdout))
        // .without_time()
        // .with_target(false)
        // .with_current_span(false)
        .try_init();
}

// goal: get trivial example running n rippin
// https://github.com/axelarnetwork/tofn/blob/main/tests/integration/single_thread/mod.rs
#[test]
pub fn run_tests() {
    do_the_thing();
}

pub fn do_the_thing() {
    // keygen
    set_up_logs();
    // keygen
    let party_share_counts = PartyShareCounts::from_vec(vec![1, 2, 3, 4]).unwrap(); // 10 total shares
    let threshold = 5;
    let sign_parties = {
        let mut sign_parties = SignParties::with_max_size(party_share_counts.party_count());
        sign_parties.add(TypedUsize::from_usize(0)).unwrap();
        sign_parties.add(TypedUsize::from_usize(1)).unwrap();
        sign_parties.add(TypedUsize::from_usize(3)).unwrap();
        sign_parties
    };
    debug!(
        "total_share_count {}, threshold {}",
        party_share_counts.total_share_count(),
        threshold,
    );

    debug!("keygen...");
    let keygen_shares = initialize_honest_parties(&party_share_counts, threshold);
    let keygen_share_outputs = execute_protocol(keygen_shares).expect("internal tofn error");
    let secret_key_shares: VecMap<KeygenShareId, SecretKeyShare> =
        keygen_share_outputs.map2(|(keygen_share_id, keygen_share)| match keygen_share {
            Protocol::NotDone(_) => panic!("share_id {} not done yet", keygen_share_id),
            Protocol::Done(result) => result.expect("share finished with error"),
        });

    debug!("sign...");

    let keygen_share_ids = VecMap::<SignShareId, _>::from_vec(
        party_share_counts.share_id_subset(&sign_parties).unwrap(),
    );
    let msg_to_sign = MessageDigest::try_from(&[42; 32][..]).unwrap();
    let sign_shares = keygen_share_ids.map(|keygen_share_id| {
        let secret_key_share = secret_key_shares.get(keygen_share_id).unwrap();
        new_sign(
            secret_key_share.group(),
            secret_key_share.share(),
            &sign_parties,
            &msg_to_sign,
            #[cfg(feature = "malicious")]
            sign::malicious::Behaviour::Honest,
        )
        .unwrap()
    });
    let sign_share_outputs = execute_protocol(sign_shares).unwrap();
    let signatures = sign_share_outputs.map(|output| match output {
        Protocol::NotDone(_) => panic!("sign share not done yet"),
        Protocol::Done(result) => result.expect("sign share finished with error"),
    });

    // grab pubkey bytes from one of the shares
    let pubkey_bytes = secret_key_shares
        .get(TypedUsize::from_usize(0))
        .unwrap()
        .group()
        .encoded_pubkey();

    // verify a signature
    let pubkey = k256::AffinePoint::from_encoded_point(
        &k256::EncodedPoint::from_bytes(pubkey_bytes).unwrap(),
    )
    .unwrap();
    let sig = k256::ecdsa::Signature::from_der(signatures.get(TypedUsize::from_usize(0)).unwrap())
        .unwrap();
    assert!(pubkey
        .verify_prehashed(&k256::Scalar::from(&msg_to_sign), &sig)
        .is_ok());
}

pub mod tofn_common {
    use tofn::{collections::TypedUsize, gg20::keygen::SecretRecoveryKey};

    pub mod keygen {

        use tofn::{
            collections::VecMap,
            gg20::keygen::{
                create_party_keypair_and_zksetup_unsafe, new_keygen, KeygenPartyId, KeygenProtocol,
                KeygenShareId,
            },
            sdk::api::PartyShareCounts,
        };

        #[cfg(feature = "malicious")]
        use tofn::gg20::keygen::malicious::Behaviour;

        pub fn initialize_honest_parties(
            party_share_counts: &PartyShareCounts<KeygenPartyId>,
            threshold: usize,
        ) -> VecMap<KeygenShareId, KeygenProtocol> {
            let session_nonce = b"foobar";

            party_share_counts
                .iter()
                .map(|(party_id, &party_share_count)| {
                    // each party use the same secret recovery key for all its subshares
                    let secret_recovery_key = super::dummy_secret_recovery_key(party_id);

                    let party_keygen_data = create_party_keypair_and_zksetup_unsafe(
                        party_id,
                        &secret_recovery_key,
                        session_nonce,
                    )
                    .unwrap();

                    (0..party_share_count).map(move |subshare_id| {
                        new_keygen(
                            party_share_counts.clone(),
                            threshold,
                            party_id,
                            subshare_id,
                            &party_keygen_data,
                            #[cfg(feature = "malicious")]
                            Behaviour::Honest,
                        )
                        .unwrap()
                    })
                })
                .flatten()
                .collect()
        }
    }

    /// return the all-zero array with the first bytes set to the bytes of `index`
    pub fn dummy_secret_recovery_key<K>(index: TypedUsize<K>) -> SecretRecoveryKey {
        let index_bytes = index.as_usize().to_be_bytes();
        let mut result = [0; 64];
        for (i, &b) in index_bytes.iter().enumerate() {
            result[i] = b;
        }
        result[..].try_into().unwrap()
    }
}
pub mod execute {
    use tofn::{
        collections::{HoleVecMap, TypedUsize, VecMap},
        sdk::api::{BytesVec, Protocol, TofnResult},
    };
    use tracing::{debug, warn};

    pub fn execute_protocol<F, K, P, const MAX_MSG_IN_LEN: usize>(
        mut parties: VecMap<K, Protocol<F, K, P, MAX_MSG_IN_LEN>>,
    ) -> TofnResult<VecMap<K, Protocol<F, K, P, MAX_MSG_IN_LEN>>>
    where
        K: Clone,
    {
        let mut current_round = 0;
        while nobody_done(&parties) {
            current_round += 1;
            parties = next_round(parties, current_round)?;
        }
        Ok(parties)
    }

    pub fn nobody_done<F, K, P, const MAX_MSG_IN_LEN: usize>(
        parties: &VecMap<K, Protocol<F, K, P, MAX_MSG_IN_LEN>>,
    ) -> bool {
        // warn if there's disagreement
        let (mut done, mut not_done) = (
            Vec::with_capacity(parties.len()),
            Vec::with_capacity(parties.len()),
        );
        for (i, party) in parties.iter() {
            if matches!(party, Protocol::Done(_)) {
                done.push(i);
            } else {
                not_done.push(i);
            }
        }
        if !done.is_empty() && !not_done.is_empty() {
            warn!(
                "disagreement: done parties {:?}, not done parties {:?}",
                done, not_done
            );
        }
        done.is_empty()
    }

    fn next_round<F, K, P, const MAX_MSG_IN_LEN: usize>(
        parties: VecMap<K, Protocol<F, K, P, MAX_MSG_IN_LEN>>,
        current_round: usize,
    ) -> TofnResult<VecMap<K, Protocol<F, K, P, MAX_MSG_IN_LEN>>>
    where
        K: Clone,
    {
        // extract current round from parties
        let mut rounds: VecMap<K, _> = parties
            .into_iter()
            .map(|(i, party)| match party {
                Protocol::NotDone(round) => round,
                Protocol::Done(_) => panic!("next_round called but party {} is done", i),
            })
            .collect();

        // deliver bcasts
        let bcasts: VecMap<K, Option<BytesVec>> = rounds
            .iter()
            .map(|(_, round)| round.bcast_out().cloned())
            .collect();
        for (from, bcast) in bcasts.into_iter() {
            if let Some(bytes) = bcast {
                if from.as_usize() == 0 {
                    debug!("round {} bcast byte length {}", current_round, bytes.len());
                }

                for (_, round) in rounds.iter_mut() {
                    round.msg_in(
                        round
                            .info()
                            .party_share_counts()
                            .share_to_party_id(from)
                            .unwrap(),
                        &bytes,
                    )?;
                }
            }
        }

        // deliver p2ps
        let all_p2ps: VecMap<K, Option<HoleVecMap<K, BytesVec>>> = rounds
            .iter()
            .map(|(_, round)| round.p2ps_out().cloned())
            .collect();
        for (from, p2ps) in all_p2ps.into_iter() {
            if let Some(p2ps) = p2ps {
                if from.as_usize() == 0 {
                    debug!(
                        "round {} p2p byte length {}",
                        current_round,
                        p2ps.get(TypedUsize::from_usize(1)).unwrap().len()
                    );
                }
                for (_, bytes) in p2ps {
                    for (_, round) in rounds.iter_mut() {
                        round.msg_in(
                            round
                                .info()
                                .party_share_counts()
                                .share_to_party_id(from)
                                .unwrap(), // no easy access to from_party_id
                            &bytes,
                        )?;
                    }
                }
            }
        }

        // compute next round's parties
        rounds
            .into_iter()
            .map(|(i, round)| {
                if round.expecting_more_msgs_this_round() {
                    warn!(
                        "all messages delivered this round but party {} still expecting messages",
                        i,
                    );
                }
                round.execute_next_round()
            })
            .collect::<TofnResult<_>>()
    }
}
