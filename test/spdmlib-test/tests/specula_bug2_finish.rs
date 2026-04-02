// Bug 2 Reproduction: FINISH Half-Commitment Leaves Session Inconsistent
//
// This test demonstrates that when the requester's generate_data_secret fails
// after the responder has already completed FINISH (session Established),
// the session becomes inconsistent: responder is Established, requester is torn down,
// and no notification is sent to the responder.
//
// The test uses a counter-based HKDF that allows the first 3 generate_data_secret
// calls to succeed (2 during setup + 1 for responder FINISH) but fails on the 4th
// call (requester FINISH), simulating a hardware/crypto error on the requester side.
//
// Copyright (c) 2025
// SPDX-License-Identifier: Apache-2.0 or MIT

#[cfg(feature = "hashed-transcript-data")]
mod bug2 {
    use codec::Writer;
    use spdmlib::common::session::{SpdmSession, SpdmSessionState};
    use spdmlib::common::SpdmCodec;
    use spdmlib::crypto::SpdmHkdf;
    use spdmlib::protocol::{
        gen_array_clone, SpdmAeadAlgo, SpdmBaseAsymAlgo, SpdmBaseHashAlgo, SpdmDheAlgo,
        SpdmDigestStruct, SpdmHkdfInputKeyingMaterial, SpdmHkdfOutputKeyingMaterial,
        SpdmHkdfPseudoRandomKey, SpdmKemAlgo, SpdmKeyScheduleAlgo,
        SpdmRequestCapabilityFlags, SpdmResponseCapabilityFlags,
        SpdmSharedSecretFinalKeyStruct, SpdmVersion, SPDM_MAX_HASH_SIZE,
        SPDM_MAX_HKDF_OKM_SIZE, SPDM_MAX_SHARED_SECRET_SIZE,
    };
    use spdmlib::requester::RequesterContext;
    use spdmlib::{crypto, responder, secret};
    use spdmlib_test::common::device_io::{FakeSpdmDeviceIo, FakeSpdmDeviceIoReceve, SharedBuffer};
    use spdmlib_test::common::secret_callback::{
        SECRET_ASYM_IMPL_INSTANCE, SECRET_PQC_ASYM_IMPL_INSTANCE,
    };
    use spdmlib_test::common::transport::PciDoeTransportEncap;
    use spdmlib_test::common::util::{create_info, get_rsp_cert_chain_buff};
    use spin::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const EXP_MASTER_LABEL: &[u8] = b"exp master";

    /// Global counter tracking how many times hkdf_expand is called with the
    /// "exp master" label (which only appears in generate_data_secret's
    /// derive_export_master_secret).
    static EXP_MASTER_COUNT: AtomicUsize = AtomicUsize::new(0);

    /// The call number at which to inject a failure. The 4th "exp master" call
    /// corresponds to the requester's generate_data_secret during FINISH.
    const FAIL_AT: usize = 4;

    fn hkdf_extract_passthrough(
        hash_algo: SpdmBaseHashAlgo,
        _salt: &[u8],
        _ikm: &SpdmHkdfInputKeyingMaterial,
    ) -> Option<SpdmHkdfPseudoRandomKey> {
        let data_size = match hash_algo {
            SpdmBaseHashAlgo::TPM_ALG_SHA_256 => 32,
            SpdmBaseHashAlgo::TPM_ALG_SHA_384 => 48,
            SpdmBaseHashAlgo::TPM_ALG_SHA_512 => 64,
            _ => return None,
        };
        Some(SpdmHkdfPseudoRandomKey {
            data_size,
            data: Box::new([0x5Au8; SPDM_MAX_HASH_SIZE]),
        })
    }

    fn hkdf_expand_fail_on_4th_exp_master(
        hash_algo: SpdmBaseHashAlgo,
        _prk: &SpdmHkdfPseudoRandomKey,
        info: &[u8],
        out_size: u16,
    ) -> Option<SpdmHkdfOutputKeyingMaterial> {
        // Check if this call is for "exp master" derivation
        if info
            .windows(EXP_MASTER_LABEL.len())
            .any(|window| window == EXP_MASTER_LABEL)
        {
            let count = EXP_MASTER_COUNT.fetch_add(1, Ordering::SeqCst) + 1;
            if count >= FAIL_AT {
                eprintln!(
                    "[BUG2 HKDF] exp master call #{count} — INJECTING FAILURE (simulating crypto error on requester)"
                );
                return None;
            }
            eprintln!("[BUG2 HKDF] exp master call #{count} — allowing");
        }

        if out_size as usize > SPDM_MAX_HKDF_OKM_SIZE {
            return None;
        }

        let data_size = match hash_algo {
            SpdmBaseHashAlgo::TPM_ALG_SHA_256
            | SpdmBaseHashAlgo::TPM_ALG_SHA_384
            | SpdmBaseHashAlgo::TPM_ALG_SHA_512 => out_size,
            _ => return None,
        };

        Some(SpdmHkdfOutputKeyingMaterial {
            data_size,
            data: Box::new([0xA5u8; SPDM_MAX_HKDF_OKM_SIZE]),
        })
    }

    #[test]
    fn repro_finish_half_commitment() {
        // Register crypto callbacks — HKDF will fail on the 4th "exp master" call
        secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
        secret::pqc_asym_sign::register(SECRET_PQC_ASYM_IMPL_INSTANCE.clone());
        assert!(spdmlib::crypto::hkdf::register(SpdmHkdf {
            hkdf_extract_cb: hkdf_extract_passthrough,
            hkdf_expand_cb: hkdf_expand_fail_on_4th_exp_master,
        }));

        let future = async {
            let (rsp_config_info, rsp_provision_info) = create_info();
            let (req_config_info, req_provision_info) = create_info();

            // --- Set up Responder ---
            let shared_buffer = SharedBuffer::new();
            let device_io_responder = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
                shared_buffer,
            ))));
            let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));

            let mut responder = responder::ResponderContext::new(
                device_io_responder,
                pcidoe_transport_encap,
                rsp_config_info,
                rsp_provision_info,
            );

            responder.common.negotiate_info.req_ct_exponent_sel = 0;
            responder.common.negotiate_info.req_capabilities_sel =
                SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;
            responder.common.negotiate_info.rsp_ct_exponent_sel = 0;
            responder.common.negotiate_info.rsp_capabilities_sel =
                SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;
            responder.common.negotiate_info.base_asym_sel =
                SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
            responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
            responder.common.provision_info.my_cert_chain = [
                Some(get_rsp_cert_chain_buff()),
                None, None, None, None, None, None, None,
            ];
            responder.common.reset_runtime_info();

            let session_id = 4294901758u32;
            responder.common.session = gen_array_clone(SpdmSession::new(), 4);
            responder.common.session[0].setup(session_id).unwrap();
            responder.common.session[0].set_crypto_param(
                SpdmBaseHashAlgo::TPM_ALG_SHA_384,
                SpdmDheAlgo::SECP_384_R1,
                SpdmKemAlgo::empty(),
                SpdmAeadAlgo::AES_256_GCM,
                SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
            );
            responder.common.session[0]
                .set_session_state(SpdmSessionState::SpdmSessionHandshaking);
            responder
                .common
                .runtime_info
                .set_last_session_id(Some(session_id));
            responder.common.session[0].runtime_info.digest_context_th = Some(
                crypto::hash::hash_ctx_init(responder.common.negotiate_info.base_hash_sel).unwrap(),
            );
            let shared_secret = SpdmSharedSecretFinalKeyStruct {
                data_size: 48,
                data: Box::new([0; SPDM_MAX_SHARED_SECRET_SIZE]),
            };
            let _ = responder.common.session[0]
                .set_shared_secret(SpdmVersion::SpdmVersion12, shared_secret);
            let _ = responder.common.session[0].generate_handshake_secret(
                SpdmVersion::SpdmVersion12,
                &SpdmDigestStruct {
                    data_size: 48,
                    data: Box::new([0; SPDM_MAX_HASH_SIZE]),
                },
            );
            // This is the 1st "exp master" call
            let _ = responder.common.session[0].generate_data_secret(
                SpdmVersion::SpdmVersion12,
                &SpdmDigestStruct {
                    data_size: 48,
                    data: Box::new([0; SPDM_MAX_HASH_SIZE]),
                },
            );

            // Keep a reference to the responder's session array to check state later
            let responder_arc = Arc::new(Mutex::new(responder));

            // --- Set up Requester ---
            let pcidoe_transport_encap2 = Arc::new(Mutex::new(PciDoeTransportEncap {}));
            let shared_buffer = SharedBuffer::new();
            let device_io_requester = Arc::new(Mutex::new(FakeSpdmDeviceIo::new(
                Arc::new(shared_buffer),
                responder_arc.clone(),
            )));

            let mut requester = RequesterContext::new(
                device_io_requester,
                pcidoe_transport_encap2,
                req_config_info,
                req_provision_info,
            );

            requester.common.negotiate_info.req_ct_exponent_sel = 0;
            requester.common.negotiate_info.req_capabilities_sel =
                SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;
            requester.common.negotiate_info.rsp_ct_exponent_sel = 0;
            requester.common.negotiate_info.rsp_capabilities_sel =
                SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;
            requester.common.negotiate_info.base_asym_sel =
                SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
            requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
            requester.common.peer_info.peer_cert_chain[0] = Some(get_rsp_cert_chain_buff());
            requester.common.reset_runtime_info();

            requester.common.session = gen_array_clone(SpdmSession::new(), 4);
            requester.common.session[0].setup(session_id).unwrap();
            requester.common.session[0].set_crypto_param(
                SpdmBaseHashAlgo::TPM_ALG_SHA_384,
                SpdmDheAlgo::SECP_384_R1,
                SpdmKemAlgo::empty(),
                SpdmAeadAlgo::AES_256_GCM,
                SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
            );
            requester.common.session[0]
                .set_session_state(SpdmSessionState::SpdmSessionHandshaking);
            requester.common.session[0].runtime_info.digest_context_th = Some(
                crypto::hash::hash_ctx_init(requester.common.negotiate_info.base_hash_sel).unwrap(),
            );
            let shared_secret = SpdmSharedSecretFinalKeyStruct {
                data_size: 48,
                data: Box::new([0; SPDM_MAX_SHARED_SECRET_SIZE]),
            };
            let _ = requester.common.session[0]
                .set_shared_secret(SpdmVersion::SpdmVersion12, shared_secret);
            let _ = requester.common.session[0].generate_handshake_secret(
                SpdmVersion::SpdmVersion12,
                &SpdmDigestStruct {
                    data_size: 48,
                    data: Box::new([0; SPDM_MAX_HASH_SIZE]),
                },
            );
            // This is the 2nd "exp master" call
            let _ = requester.common.session[0].generate_data_secret(
                SpdmVersion::SpdmVersion12,
                &SpdmDigestStruct {
                    data_size: 48,
                    data: Box::new([0; SPDM_MAX_HASH_SIZE]),
                },
            );

            assert_eq!(
                EXP_MASTER_COUNT.load(Ordering::SeqCst),
                2,
                "setup should have triggered exactly 2 exp-master derivations"
            );

            // --- Execute FINISH exchange ---
            // The responder's FINISH handler will call generate_data_secret (3rd "exp master" — succeeds).
            // The requester's FINISH response handler will call generate_data_secret (4th "exp master" — FAILS).
            let result = requester
                .send_receive_spdm_finish(None, session_id)
                .await;

            // The requester's FINISH should fail because generate_data_secret failed
            assert!(
                result.is_err(),
                "FINISH should fail on requester due to injected crypto error"
            );

            // Verify: requester session is torn down
            assert_eq!(
                requester.common.session[0].get_session_id(),
                spdmlib::common::INVALID_SESSION_ID,
                "requester session should be torn down after generate_data_secret failure"
            );

            // Verify: responder session is STILL Established
            // This is the core of the bug: the responder has already committed to Established
            // but the requester failed and tore down its session.
            let responder = responder_arc.lock();
            let rsp_session_state = responder.common.session[0].get_session_state();
            assert_eq!(
                rsp_session_state,
                SpdmSessionState::SpdmSessionEstablished,
                "BUG CONFIRMED: responder is Established while requester is torn down — \
                 no protocol mechanism exists to notify the responder of the failure"
            );

            // Verify: the exp master counter confirms the failure was injected at the right point
            let final_count = EXP_MASTER_COUNT.load(Ordering::SeqCst);
            assert!(
                final_count >= FAIL_AT,
                "exp-master counter should have reached the failure point (got {final_count})"
            );

            eprintln!("\n=== BUG 2 REPRODUCED ===");
            eprintln!("Responder session state: {:?}", rsp_session_state);
            eprintln!(
                "Requester session ID: {} (INVALID={})",
                requester.common.session[0].get_session_id(),
                spdmlib::common::INVALID_SESSION_ID,
            );
            eprintln!("The responder is Established but the requester has torn down.");
            eprintln!("No protocol mechanism exists to notify the responder.");
            eprintln!("========================\n");
        };
        executor::block_on(future);
    }
}
