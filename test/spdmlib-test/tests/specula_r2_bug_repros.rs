// Specula Round 2 Bug Reproductions for spdm-rs
//
// Bugs R2-1 through R2-4: found by TLA+ model checking
// Bugs TV-1, TV-2: found by code review
//
// Copyright (c) 2025
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::{Codec, Reader, Writer};
use spdmlib::common::SpdmCodec;
use spdmlib::common::session::{SpdmSession, SpdmSessionState};
use spdmlib::crypto::SpdmHkdf;
use spdmlib::message::*;
use spdmlib::protocol::*;
use spdmlib::responder::ResponderContext;
use spdmlib::requester::RequesterContext;
use spdmlib::secret;
use spdmlib_test::common::device_io::{FakeSpdmDeviceIoReceve, SharedBuffer};
use spdmlib_test::common::secret_callback::{
    SECRET_ASYM_IMPL_INSTANCE, SECRET_PQC_ASYM_IMPL_INSTANCE,
};
use spdmlib_test::common::transport::PciDoeTransportEncap;
use spdmlib_test::common::util::create_info;
use spin::Mutex;
use std::sync::Arc;
use std::sync::Once;

static INIT_CRYPTO: Once = Once::new();

fn register_crypto() {
    INIT_CRYPTO.call_once(|| {
        secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
        secret::pqc_asym_sign::register(SECRET_PQC_ASYM_IMPL_INSTANCE.clone());
        spdmlib::crypto::hkdf::register(SpdmHkdf {
            hkdf_extract_cb: hkdf_extract_passthrough,
            hkdf_expand_cb: hkdf_expand_passthrough,
        });
    });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

fn hkdf_expand_passthrough(
    hash_algo: SpdmBaseHashAlgo,
    _prk: &SpdmHkdfPseudoRandomKey,
    _info: &[u8],
    out_size: u16,
) -> Option<SpdmHkdfOutputKeyingMaterial> {
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

fn setup_established_session(session: &mut SpdmSession, session_id: u32) {
    session.setup(session_id).expect("setup session");
    session.set_crypto_param(
        SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        SpdmDheAlgo::SECP_384_R1,
        SpdmKemAlgo::empty(),
        SpdmAeadAlgo::AES_256_GCM,
        SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
    );
    session.set_session_state(SpdmSessionState::SpdmSessionEstablished);
    session
        .set_shared_secret(
            SpdmVersion::SpdmVersion12,
            SpdmSharedSecretFinalKeyStruct {
                data_size: 48,
                data: Box::new([0u8; SPDM_MAX_SHARED_SECRET_SIZE]),
            },
        )
        .expect("shared secret");
    session
        .generate_handshake_secret(
            SpdmVersion::SpdmVersion12,
            &SpdmDigestStruct {
                data_size: 48,
                data: Box::new([0u8; SPDM_MAX_HASH_SIZE]),
            },
        )
        .expect("handshake secret");
    session
        .generate_data_secret(
            SpdmVersion::SpdmVersion12,
            &SpdmDigestStruct {
                data_size: 48,
                data: Box::new([0u8; SPDM_MAX_HASH_SIZE]),
            },
        )
        .expect("data secret");
}

fn make_responder() -> ResponderContext {
    let (rsp_config_info, rsp_provision_info) = create_info();
    let shared_buffer = SharedBuffer::new();
    let device_io = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
        shared_buffer,
    ))));
    let transport = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    ResponderContext::new(device_io, transport, rsp_config_info, rsp_provision_info)
}

fn make_requester() -> RequesterContext {
    let (config_info, provision_info) = create_info();
    let shared_buffer = SharedBuffer::new();
    let device_io = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
        shared_buffer,
    ))));
    let transport = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    RequesterContext::new(device_io, transport, config_info, provision_info)
}

// ---------------------------------------------------------------------------
// Bug R2-1: Stale session state on slot reuse
//
// set_default() (called by teardown) omits resetting th1, th2,
// requester_backup_valid, and responder_backup_valid.
// When a session slot is reused via setup(), stale state persists.
// ---------------------------------------------------------------------------

#[test]
fn repro_r2_1_stale_state_after_teardown() {
    register_crypto();

    let mut session = SpdmSession::new();
    let session_id = 0x00FF_FFFEu32;

    // 1. Establish session and populate fields that set_default will miss
    setup_established_session(&mut session, session_id);

    // Perform a key update to set backup_valid = true
    session
        .create_data_secret_update(SpdmVersion::SpdmVersion12, true, true)
        .expect("key update");
    assert!(
        session.get_requester_backup_valid(),
        "precondition: requester_backup_valid should be true after key update"
    );
    assert!(
        session.get_responder_backup_valid(),
        "precondition: responder_backup_valid should be true after key update"
    );

    // Set th1 and th2 to non-default values
    let th = SpdmDigestStruct {
        data_size: 48,
        data: Box::new([0xABu8; SPDM_MAX_HASH_SIZE]),
    };
    session.set_th1(th.clone());
    session.set_th2(th.clone());
    assert_eq!(session.get_th1().data_size, 48, "precondition: th1 set");
    assert_eq!(session.get_th2().data_size, 48, "precondition: th2 set");

    // 2. Teardown the session
    session.teardown();

    // 3. Verify stale state persists (this is the bug)
    assert_eq!(
        session.get_session_id(),
        spdmlib::common::INVALID_SESSION_ID,
        "session_id should be reset after teardown"
    );

    let stale_backup_req = session.get_requester_backup_valid();
    let stale_backup_rsp = session.get_responder_backup_valid();
    let stale_th1 = session.get_th1();
    let stale_th2 = session.get_th2();

    eprintln!("\n=== BUG R2-1 REPRODUCTION ===");
    eprintln!("After teardown:");
    eprintln!("  session_id: {} (INVALID={})", session.get_session_id(), spdmlib::common::INVALID_SESSION_ID);
    eprintln!("  requester_backup_valid: {} (should be false)", stale_backup_req);
    eprintln!("  responder_backup_valid: {} (should be false)", stale_backup_rsp);
    eprintln!("  th1.data_size: {} (should be 0)", stale_th1.data_size);
    eprintln!("  th2.data_size: {} (should be 0)", stale_th2.data_size);

    // The bug: these should all be false/default after teardown, but they're not
    assert!(
        stale_backup_req,
        "BUG R2-1 CONFIRMED: requester_backup_valid persists after teardown"
    );
    assert!(
        stale_backup_rsp,
        "BUG R2-1 CONFIRMED: responder_backup_valid persists after teardown"
    );
    assert_eq!(
        stale_th1.data_size, 48,
        "BUG R2-1 CONFIRMED: th1 persists after teardown"
    );
    assert_eq!(
        stale_th2.data_size, 48,
        "BUG R2-1 CONFIRMED: th2 persists after teardown"
    );

    // 4. Reuse the slot — stale state carries over to new session
    session.setup(0x00FF_FFFDu32).expect("setup reuse");
    let reuse_backup_req = session.get_requester_backup_valid();
    let reuse_th1 = session.get_th1();
    eprintln!("\nAfter slot reuse (setup with new session_id):");
    eprintln!("  requester_backup_valid: {} (should be false)", reuse_backup_req);
    eprintln!("  th1.data_size: {} (should be 0)", reuse_th1.data_size);
    eprintln!("=== BUG R2-1 REPRODUCED ===\n");

    assert!(
        reuse_backup_req,
        "BUG R2-1 CONFIRMED: stale backup_valid inherited by new session"
    );
    assert_eq!(
        reuse_th1.data_size, 48,
        "BUG R2-1 CONFIRMED: stale th1 inherited by new session"
    );
}

// ---------------------------------------------------------------------------
// Bug R2-2: GET_VERSION reset_context leaves stale session state
//
// reset_context() calls set_default() on all sessions, inheriting the same
// incomplete reset as R2-1. An established session with populated
// transcript hashes and backup flags retains stale state after GET_VERSION.
// ---------------------------------------------------------------------------

#[test]
fn repro_r2_2_stale_state_after_reset_context() {
    register_crypto();

    let mut responder = make_responder();
    let session_id = 0x00FF_FFFEu32;

    // 1. Set up an established session on slot 0
    responder.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
    responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    responder.common.session = gen_array_clone(SpdmSession::new(), 4);
    setup_established_session(&mut responder.common.session[0], session_id);

    // Trigger backup_valid and set transcript hashes
    responder.common.session[0]
        .create_data_secret_update(SpdmVersion::SpdmVersion12, true, true)
        .expect("key update");
    let th = SpdmDigestStruct {
        data_size: 48,
        data: Box::new([0xCDu8; SPDM_MAX_HASH_SIZE]),
    };
    responder.common.session[0].set_th1(th.clone());

    assert!(responder.common.session[0].get_requester_backup_valid());
    assert_eq!(responder.common.session[0].get_th1().data_size, 48);

    // 2. Simulate GET_VERSION by calling reset_context
    responder.common.reset_context();

    // 3. Check stale state
    let s = &responder.common.session[0];
    let stale_backup = s.get_requester_backup_valid();
    let stale_th1 = s.get_th1();

    eprintln!("\n=== BUG R2-2 REPRODUCTION ===");
    eprintln!("After reset_context (simulating GET_VERSION):");
    eprintln!("  session_id: {}", s.get_session_id());
    eprintln!("  requester_backup_valid: {} (should be false)", stale_backup);
    eprintln!("  th1.data_size: {} (should be 0)", stale_th1.data_size);

    assert_eq!(
        s.get_session_id(),
        spdmlib::common::INVALID_SESSION_ID,
        "session_id should be reset"
    );
    assert!(
        stale_backup,
        "BUG R2-2 CONFIRMED: requester_backup_valid persists after reset_context"
    );
    assert_eq!(
        stale_th1.data_size, 48,
        "BUG R2-2 CONFIRMED: th1 persists after reset_context"
    );
    eprintln!("=== BUG R2-2 REPRODUCED ===\n");
}

// ---------------------------------------------------------------------------
// Bug R2-3: Missing capability gating on heartbeat handler
//
// The responder's heartbeat handler processes heartbeat requests without
// checking HBEAT_CAP. A requester can send heartbeats even when neither
// side advertised the capability.
// ---------------------------------------------------------------------------

#[test]
fn repro_r2_3_heartbeat_without_capability() {
    register_crypto();

    let mut responder = make_responder();
    let session_id = 0x00FF_FFFEu32;

    // 1. Set up responder with NO HBEAT_CAP in either side's capabilities
    responder.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
    responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;

    // Clear HBEAT_CAP and KEY_UPD_CAP from both sides
    responder.common.negotiate_info.req_capabilities_sel =
        SpdmRequestCapabilityFlags::CERT_CAP
            | SpdmRequestCapabilityFlags::ENCRYPT_CAP
            | SpdmRequestCapabilityFlags::MAC_CAP
            | SpdmRequestCapabilityFlags::KEY_EX_CAP;
    // Explicitly: NO HBEAT_CAP, NO KEY_UPD_CAP
    responder.common.negotiate_info.rsp_capabilities_sel =
        SpdmResponseCapabilityFlags::CERT_CAP
            | SpdmResponseCapabilityFlags::ENCRYPT_CAP
            | SpdmResponseCapabilityFlags::MAC_CAP
            | SpdmResponseCapabilityFlags::KEY_EX_CAP;
    // Explicitly: NO HBEAT_CAP, NO KEY_UPD_CAP

    assert!(
        !responder.common.negotiate_info.req_capabilities_sel
            .contains(SpdmRequestCapabilityFlags::HBEAT_CAP),
        "precondition: HBEAT_CAP not in req capabilities"
    );
    assert!(
        !responder.common.negotiate_info.rsp_capabilities_sel
            .contains(SpdmResponseCapabilityFlags::HBEAT_CAP),
        "precondition: HBEAT_CAP not in rsp capabilities"
    );

    // Set up an established session
    responder.common.session = gen_array_clone(SpdmSession::new(), 4);
    setup_established_session(&mut responder.common.session[0], session_id);

    // 2. Build a heartbeat request
    let request = SpdmMessage {
        header: SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion12,
            request_response_code: SpdmRequestResponseCode::SpdmRequestHeartbeat,
        },
        payload: SpdmMessagePayload::SpdmHeartbeatRequest(SpdmHeartbeatRequestPayload {}),
    };
    let mut request_bytes = [0u8; 1024];
    let mut request_writer = Writer::init(&mut request_bytes);
    request
        .spdm_encode(&mut responder.common, &mut request_writer)
        .expect("encode heartbeat request");

    // 3. Send heartbeat to responder — should be rejected but isn't
    let mut response_bytes = [0u8; 1024];
    let mut response_writer = Writer::init(&mut response_bytes);
    let (status, response) = responder.handle_spdm_heartbeat(
        session_id,
        request_writer.used_slice(),
        &mut response_writer,
    );

    eprintln!("\n=== BUG R2-3 REPRODUCTION ===");
    eprintln!("Heartbeat sent with HBEAT_CAP NOT negotiated by either side.");
    eprintln!("Handler status: {:?}", status);

    // 4. Check: the handler processed it and returned success + HeartbeatAck
    if let (Ok(()), Some(resp_buf)) = (status, response) {
        let mut reader = Reader::init(resp_buf);
        if let Some(header) = SpdmMessageHeader::read(&mut reader) {
            eprintln!("Response code: {:?}", header.request_response_code);
            if header.request_response_code
                == SpdmRequestResponseCode::SpdmResponseHeartbeatAck
            {
                eprintln!("BUG R2-3 CONFIRMED: Responder sent HeartbeatAck without HBEAT_CAP!");
                eprintln!("=== BUG R2-3 REPRODUCED ===\n");
                // Test passes — bug is reproduced
                return;
            }
        }
    }

    // If we get here, the handler correctly rejected the heartbeat (bug is fixed)
    panic!(
        "BUG R2-3 NOT REPRODUCED: heartbeat was correctly rejected \
         (status={:?}). The capability check may have been added.",
        status
    );
}

// ---------------------------------------------------------------------------
// Bug R2-4: Algorithm negotiation trust-without-verification
//
// The requester stores the responder's algorithm selections without checking
// they are a subset of the proposed set. A malicious responder can force
// any algorithm.
// ---------------------------------------------------------------------------

#[test]
fn repro_r2_4_algo_trust_without_verify() {
    register_crypto();

    let mut requester = make_requester();

    // 1. Configure requester to only support SHA-256 for base_hash
    requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
    requester.common.config_info.base_hash_algo = SpdmBaseHashAlgo::TPM_ALG_SHA_256;
    // The requester proposes ONLY SHA-256

    // Also set base_asym to a single algorithm to keep things simple
    requester.common.config_info.base_asym_algo =
        SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;

    // 2. Craft an ALGORITHMS response that selects SHA-384 (NOT in proposed set)
    let malicious_response = SpdmMessage {
        header: SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion12,
            request_response_code: SpdmRequestResponseCode::SpdmResponseAlgorithms,
        },
        payload: SpdmMessagePayload::SpdmAlgorithmsResponse(SpdmAlgorithmsResponsePayload {
            measurement_specification_sel: SpdmMeasurementSpecification::DMTF,
            other_params_selection: SpdmAlgoOtherParams::OPAQUE_DATA_FMT1,
            measurement_hash_algo: SpdmMeasurementHashAlgo::TPM_ALG_SHA_384,
            base_asym_sel: SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
            // SHA-384 selected by responder — NOT in requester's proposed set (SHA-256 only)
            base_hash_sel: SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            pqc_asym_sel: SpdmPqcAsymAlgo::empty(),
            mel_specification_sel: SpdmMelSpecification::empty(),
            alg_struct_count: 0,
            alg_struct: gen_array_clone(
                SpdmAlgStruct::default(),
                MAX_SUPPORTED_ALG_STRUCTURE_COUNT,
            ),
        }),
    };

    // Encode the response
    let mut resp_bytes = [0u8; 2048];
    let mut resp_writer = Writer::init(&mut resp_bytes);
    malicious_response
        .spdm_encode(&mut requester.common, &mut resp_writer)
        .expect("encode algorithms response");

    // Also need a dummy send_buffer (used for transcript only)
    let send_buffer = [0u8; 64];

    // 3. Call the handler
    let result = requester.handle_spdm_algorithm_response(
        0, // session_id (not used for algorithms)
        &send_buffer,
        resp_writer.used_slice(),
    );

    eprintln!("\n=== BUG R2-4 REPRODUCTION ===");
    eprintln!("Requester config_info.base_hash_algo: SHA-256 only");
    eprintln!("Responder selected: SHA-384 (NOT in proposed set)");
    eprintln!("handle_spdm_algorithm_response result: {:?}", result);
    eprintln!(
        "negotiate_info.base_hash_sel: {:?}",
        requester.common.negotiate_info.base_hash_sel
    );

    // 4. The bug: the handler should reject SHA-384 since we only proposed SHA-256,
    //    but it accepts it.
    if result.is_ok()
        && requester.common.negotiate_info.base_hash_sel == SpdmBaseHashAlgo::TPM_ALG_SHA_384
    {
        eprintln!(
            "BUG R2-4 CONFIRMED: Requester accepted SHA-384 despite only proposing SHA-256!"
        );
        eprintln!("A malicious responder can force any algorithm.");
        eprintln!("=== BUG R2-4 REPRODUCED ===\n");
        // Test passes — bug reproduced
        return;
    }

    panic!(
        "BUG R2-4 NOT REPRODUCED: handler rejected the non-proposed algorithm \
         (result={:?}, sel={:?}). The subset check may have been added.",
        result,
        requester.common.negotiate_info.base_hash_sel,
    );
}

// ---------------------------------------------------------------------------
// Bug TV-1: setup() panics on occupied slot
//
// SpdmSession::setup() calls panic!() instead of returning Err when the
// session slot is already occupied. A malicious requester could crash
// the responder.
// ---------------------------------------------------------------------------

#[test]
fn repro_tv1_setup_panic_on_occupied_slot() {
    let mut session = SpdmSession::new();

    // First setup succeeds
    session.setup(0x00FF_FFFEu32).expect("first setup");
    assert_eq!(session.get_session_id(), 0x00FF_FFFEu32);

    // Second setup on occupied slot should return Err, but instead panics
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        session.setup(0x00FF_FFFDu32)
    }));

    eprintln!("\n=== BUG TV-1 REPRODUCTION ===");
    match &result {
        Err(_) => {
            eprintln!("BUG TV-1 CONFIRMED: setup() panicked on occupied slot instead of returning Err");
            eprintln!("A malicious requester can crash the responder.");
            eprintln!("=== BUG TV-1 REPRODUCED ===\n");
        }
        Ok(Ok(())) => {
            panic!("TV-1 NOT REPRODUCED: setup() succeeded on occupied slot (unexpected)");
        }
        Ok(Err(e)) => {
            panic!(
                "TV-1 NOT REPRODUCED: setup() correctly returned Err on occupied slot: {:?}",
                e
            );
        }
    }

    assert!(result.is_err(), "setup() should have panicked");
}

// ---------------------------------------------------------------------------
// Bug TV-2: PQC req_asym algorithm priority inverted
//
// SpdmPqcReqAsymAlgo::prioritize() lists [MLDSA-44, MLDSA-65, MLDSA-87]
// (weakest first), while the corresponding SpdmPqcAsymAlgo::prioritize()
// correctly lists [MLDSA-87, MLDSA-65, MLDSA-44] (strongest first).
// ---------------------------------------------------------------------------

#[test]
fn repro_tv2_pqc_priority_inversion() {
    // Test SpdmPqcReqAsymAlgo — the buggy one
    let mut req_asym = SpdmPqcReqAsymAlgo::ALG_MLDSA_44
        | SpdmPqcReqAsymAlgo::ALG_MLDSA_65
        | SpdmPqcReqAsymAlgo::ALG_MLDSA_87;

    let peer = SpdmPqcReqAsymAlgo::ALG_MLDSA_44
        | SpdmPqcReqAsymAlgo::ALG_MLDSA_65
        | SpdmPqcReqAsymAlgo::ALG_MLDSA_87;

    req_asym.prioritize(peer);

    eprintln!("\n=== BUG TV-2 REPRODUCTION ===");
    eprintln!("SpdmPqcReqAsymAlgo with all 3 algos after prioritize():");
    eprintln!("  Selected: {:?} (bits: 0x{:x})", req_asym, req_asym.bits());
    eprintln!("  MLDSA-44 bits: 0x{:x}", SpdmPqcReqAsymAlgo::ALG_MLDSA_44.bits());
    eprintln!("  MLDSA-87 bits: 0x{:x}", SpdmPqcReqAsymAlgo::ALG_MLDSA_87.bits());

    // Compare with SpdmPqcAsymAlgo — the correct one
    let mut pqc_asym = SpdmPqcAsymAlgo::ALG_MLDSA_44
        | SpdmPqcAsymAlgo::ALG_MLDSA_65
        | SpdmPqcAsymAlgo::ALG_MLDSA_87;

    let pqc_peer = SpdmPqcAsymAlgo::ALG_MLDSA_44
        | SpdmPqcAsymAlgo::ALG_MLDSA_65
        | SpdmPqcAsymAlgo::ALG_MLDSA_87;

    pqc_asym.prioritize(pqc_peer);

    eprintln!("SpdmPqcAsymAlgo with all 3 algos after prioritize():");
    eprintln!("  Selected: {:?} (bits: 0x{:x})", pqc_asym, pqc_asym.bits());
    eprintln!("  Expected: MLDSA-87 (strongest)");

    // PqcAsymAlgo correctly selects MLDSA-87 (strongest)
    assert_eq!(
        pqc_asym,
        SpdmPqcAsymAlgo::ALG_MLDSA_87,
        "SpdmPqcAsymAlgo should select MLDSA-87 (strongest first)"
    );

    // PqcReqAsymAlgo incorrectly selects MLDSA-44 (weakest)
    if req_asym == SpdmPqcReqAsymAlgo::ALG_MLDSA_44 {
        eprintln!(
            "BUG TV-2 CONFIRMED: SpdmPqcReqAsymAlgo selects MLDSA-44 (weakest) \
             instead of MLDSA-87 (strongest)"
        );
        eprintln!("=== BUG TV-2 REPRODUCED ===\n");
    } else {
        panic!(
            "TV-2 NOT REPRODUCED: PqcReqAsymAlgo selected {:?}, expected MLDSA-44 for bug",
            req_asym
        );
    }
}
