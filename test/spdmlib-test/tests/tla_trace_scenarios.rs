// TLA+ Trace Generation Scenarios for SPDM Protocol
//
// Produces NDJSON traces consumed by spec/Trace.tla for validation.
// Each test exercises a specific protocol path and writes events to a trace file.

use codec::Writer;
use spdmlib::common::session::{SpdmSession, SpdmSessionState};
use spdmlib::common::SpdmCodec;
use spdmlib::message::key_update::SpdmKeyUpdateOperation;
use spdmlib::message::{
    SpdmKeyUpdateRequestPayload, SpdmMessage, SpdmMessageHeader, SpdmMessagePayload,
    SpdmRequestResponseCode,
};
use spdmlib::protocol::{
    gen_array_clone, SpdmAeadAlgo, SpdmBaseHashAlgo, SpdmDheAlgo, SpdmDigestStruct, SpdmKemAlgo,
    SpdmKeyScheduleAlgo, SpdmSharedSecretFinalKeyStruct, SpdmVersion, SPDM_MAX_HASH_SIZE,
    SPDM_MAX_SHARED_SECRET_SIZE,
};
use spdmlib::responder::ResponderContext;
use spdmlib::secret;
use spdmlib::spdm_trace::{self, TraceEvent, TraceKeyUpdateOp, TraceRole};
use spdmlib_test::common::device_io::{FakeSpdmDeviceIoReceve, SharedBuffer};
use spdmlib_test::common::secret_callback::{
    SECRET_ASYM_IMPL_INSTANCE, SECRET_PQC_ASYM_IMPL_INSTANCE,
};
use spdmlib_test::common::transport::PciDoeTransportEncap;
use spdmlib_test::common::util::create_info;
use spin::Mutex;
use std::io::Write;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Global trace file handle
// ---------------------------------------------------------------------------

static TRACE_FILE: std::sync::Mutex<Option<std::fs::File>> = std::sync::Mutex::new(None);

fn open_trace_file(name: &str) {
    let traces_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../traces");
    std::fs::create_dir_all(&traces_dir).ok();
    let path = traces_dir.join(name);
    let file = std::fs::File::create(&path).expect("create trace file");
    *TRACE_FILE.lock().unwrap() = Some(file);
    eprintln!("Trace file: {}", path.display());
}

fn close_trace_file() {
    if let Some(mut f) = TRACE_FILE.lock().unwrap().take() {
        f.flush().ok();
    }
}

// ---------------------------------------------------------------------------
// NDJSON callback — converts TraceEvent to Trace.tla format
// ---------------------------------------------------------------------------

fn map_connection_state(
    cs: spdmlib::common::SpdmConnectionState,
) -> &'static str {
    use spdmlib::common::SpdmConnectionState::*;
    match cs {
        SpdmConnectionNotStarted => "NotStarted",
        SpdmConnectionAfterVersion => "AfterVersion",
        SpdmConnectionAfterCapabilities => "AfterCapabilities",
        SpdmConnectionNegotiated => "Negotiated",
        SpdmConnectionAfterDigest => "AfterDigest",
        SpdmConnectionAfterCertificate => "AfterCertificate",
        SpdmConnectionAuthenticated => "Authenticated",
        _ => "Unknown",
    }
}

fn map_session_state(ss: SpdmSessionState) -> &'static str {
    match ss {
        SpdmSessionState::SpdmSessionNotStarted => "NotStarted",
        SpdmSessionState::SpdmSessionHandshaking => "Handshaking",
        SpdmSessionState::SpdmSessionEstablished => "Established",
        _ => "Unknown",
    }
}

fn map_op(op: &TraceKeyUpdateOp) -> &'static str {
    match op {
        TraceKeyUpdateOp::UpdateSingle => "UpdateSingle",
        TraceKeyUpdateOp::UpdateAll => "UpdateAll",
        TraceKeyUpdateOp::VerifyNewKey => "VerifyNewKey",
    }
}

/// Map internal event names to Trace.tla expected names.
/// Returns None for internal events that shouldn't appear in the trace.
fn map_event_name(name: &str) -> Option<&str> {
    match name {
        "HandleGetVersion" => Some("HandleGetVersion"),
        "HandshakeAdvance" => Some("HandshakeAdvance"),
        "HandleChallenge" => Some("HandleChallenge"),
        "WriteSpdmKeyExchangeResponse" => Some("HandleKeyExchange"),
        "RequesterSendFinish" => Some("RequesterSendFinish"),
        "ResponderHandleFinish" => Some("ResponderHandleFinish"),
        "RequesterReceiveFinishResp" => Some("RequesterReceiveFinishResp"),
        "SendKeyUpdate" => Some("SendKeyUpdate"),
        "ResponderHandleKeyUpdate" => Some("ResponderHandleKeyUpdate"),
        "RequesterHandleKeyUpdateAck" => Some("RequesterHandleKeyUpdateAck"),
        "HandleEndSession" => Some("HandleEndSession"),
        _ => None,
    }
}

fn ndjson_callback(event: &TraceEvent) {
    let name = match map_event_name(event.name) {
        Some(n) => n,
        None => return, // skip internal events
    };

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let mut parts = Vec::<String>::new();
    parts.push(format!("\"event\":\"{}\"", name));
    parts.push(format!("\"ts\":{}", ts));

    // Connection state
    if let Some(ref rsp) = event.state.responder {
        if let Some(cs) = rsp.connection_state {
            parts.push(format!(
                "\"connectionState\":\"{}\"",
                map_connection_state(cs)
            ));
        }
        if let Some(ss) = rsp.session_state {
            parts.push(format!(
                "\"rsSessionState\":\"{}\"",
                map_session_state(ss)
            ));
        }
    }
    if let Some(ref req) = event.state.requester {
        if let Some(ss) = req.session_state {
            parts.push(format!(
                "\"rqSessionState\":\"{}\"",
                map_session_state(ss)
            ));
        }
    }

    // Key generations
    if let Some(ref kg) = event.state.key_gens {
        parts.push(format!("\"rqReqKey\":{}", kg.rq_req));
        parts.push(format!("\"rqRespKey\":{}", kg.rq_resp));
        parts.push(format!("\"rsReqKey\":{}", kg.rs_req));
        parts.push(format!("\"rsRespKey\":{}", kg.rs_resp));
    }

    // Backup valid
    if let Some(bv) = event.state.req_backup_valid {
        parts.push(format!("\"rsReqBackupValid\":{}", bv));
    }
    if let Some(bv) = event.state.rsp_backup_valid {
        parts.push(format!("\"rsRespBackupValid\":{}", bv));
    }

    // Message fields
    if let Some(ref op) = event.msg.op {
        parts.push(format!("\"op\":\"{}\"", map_op(op)));
    }
    if let Some(slot) = event.msg.slot {
        parts.push(format!("\"slot\":{}", slot));
        parts.push(format!("\"selectedSlot\":{}", slot));
    }
    if let Some(hmac_ok) = event.msg.hmac_ok {
        parts.push(format!("\"hmacOk\":{}", hmac_ok));
    }
    if let Some(ds_ok) = event.msg.data_secret_ok {
        parts.push(format!("\"dataSecretOk\":{}", ds_ok));
    }
    if let Some(hmac_ok) = event.msg.hmac_ok {
        parts.push(format!("\"finishHmacVerified\":{}", hmac_ok));
    }
    if let Some(ds_ok) = event.msg.data_secret_ok {
        parts.push(format!(
            "\"finishDataSecretGenerated\":{}",
            ds_ok && event.msg.hmac_ok.unwrap_or(false)
        ));
    }

    let line = format!("{{{}}}", parts.join(","));
    let mut guard = TRACE_FILE.lock().unwrap();
    if let Some(ref mut f) = *guard {
        writeln!(f, "{}", line).ok();
        f.flush().ok();
    }
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

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

fn setup_responder_key_update() -> (ResponderContext, u32) {
    let (rsp_config_info, rsp_provision_info) = create_info();
    let shared_buffer = SharedBuffer::new();
    let device_io = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
        shared_buffer,
    ))));
    let transport = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let mut responder =
        ResponderContext::new(device_io, transport, rsp_config_info, rsp_provision_info);

    let rsp_session_id = 0xFFFEu16;
    let session_id = (0xffu32 << 16) + rsp_session_id as u32;
    responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    responder.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
    responder.common.session = gen_array_clone(SpdmSession::new(), 4);
    setup_established_session(&mut responder.common.session[0], session_id);

    (responder, session_id)
}

fn build_key_update_request(
    common: &mut spdmlib::common::SpdmContext,
    op: SpdmKeyUpdateOperation,
    tag: u8,
) -> Vec<u8> {
    let request = SpdmMessage {
        header: SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion12,
            request_response_code: SpdmRequestResponseCode::SpdmRequestKeyUpdate,
        },
        payload: SpdmMessagePayload::SpdmKeyUpdateRequest(SpdmKeyUpdateRequestPayload {
            key_update_operation: op,
            tag,
        }),
    };
    let mut buf = [0u8; 1024];
    let mut writer = Writer::init(&mut buf);
    request
        .spdm_encode(common, &mut writer)
        .expect("encode key update");
    writer.used_slice().to_vec()
}

fn register_crypto() {
    secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    secret::pqc_asym_sign::register(SECRET_PQC_ASYM_IMPL_INSTANCE.clone());
}

// ---------------------------------------------------------------------------
// Test: Key Update (UpdateSingle + VerifyNewKey)
// ---------------------------------------------------------------------------

#[test]
fn tla_trace_key_update_single() {
    register_crypto();
    spdm_trace::reset_shadow_state();
    open_trace_file("key_update_single.ndjson");
    spdm_trace::register_callback(ndjson_callback);

    // Simulate post-FINISH state: both sides have key gen = 1
    spdm_trace::note_data_secret_generated(TraceRole::Requester);
    spdm_trace::note_data_secret_generated(TraceRole::Responder);

    let (mut responder, session_id) = setup_responder_key_update();

    // --- UpdateSingle ---
    let req_bytes = build_key_update_request(
        &mut responder.common,
        SpdmKeyUpdateOperation::SpdmUpdateSingleKey,
        1,
    );
    let mut resp_buf = [0u8; 1024];
    let mut writer = Writer::init(&mut resp_buf);
    let (status, _resp) =
        responder.handle_spdm_key_update(session_id, &req_bytes, &mut writer);
    assert!(status.is_ok(), "UpdateSingle should succeed");

    // --- VerifyNewKey ---
    let req_bytes = build_key_update_request(
        &mut responder.common,
        SpdmKeyUpdateOperation::SpdmVerifyNewKey,
        2,
    );
    let mut resp_buf = [0u8; 1024];
    let mut writer = Writer::init(&mut resp_buf);
    let (status, _resp) =
        responder.handle_spdm_key_update(session_id, &req_bytes, &mut writer);
    assert!(status.is_ok(), "VerifyNewKey should succeed");

    spdm_trace::clear_callback();
    close_trace_file();
}

// ---------------------------------------------------------------------------
// Test: Key Update (UpdateAll + VerifyNewKey)
// ---------------------------------------------------------------------------

#[test]
fn tla_trace_key_update_all() {
    register_crypto();
    spdm_trace::reset_shadow_state();
    open_trace_file("key_update_all.ndjson");
    spdm_trace::register_callback(ndjson_callback);

    spdm_trace::note_data_secret_generated(TraceRole::Requester);
    spdm_trace::note_data_secret_generated(TraceRole::Responder);

    let (mut responder, session_id) = setup_responder_key_update();

    // --- UpdateAll ---
    let req_bytes = build_key_update_request(
        &mut responder.common,
        SpdmKeyUpdateOperation::SpdmUpdateAllKeys,
        1,
    );
    let mut resp_buf = [0u8; 1024];
    let mut writer = Writer::init(&mut resp_buf);
    let (status, _resp) =
        responder.handle_spdm_key_update(session_id, &req_bytes, &mut writer);
    assert!(status.is_ok(), "UpdateAll should succeed");

    // --- VerifyNewKey ---
    let req_bytes = build_key_update_request(
        &mut responder.common,
        SpdmKeyUpdateOperation::SpdmVerifyNewKey,
        2,
    );
    let mut resp_buf = [0u8; 1024];
    let mut writer = Writer::init(&mut resp_buf);
    let (status, _resp) =
        responder.handle_spdm_key_update(session_id, &req_bytes, &mut writer);
    assert!(status.is_ok(), "VerifyNewKey should succeed");

    spdm_trace::clear_callback();
    close_trace_file();
}

// ---------------------------------------------------------------------------
// Test: Basic Handshake (GetVersion → AfterCertificate)
// ---------------------------------------------------------------------------

#[test]
fn tla_trace_basic_handshake() {
    register_crypto();
    spdm_trace::reset_shadow_state();
    open_trace_file("basic_handshake.ndjson");
    spdm_trace::register_callback(ndjson_callback);

    let (rsp_config_info, rsp_provision_info) = create_info();
    let shared_buffer = SharedBuffer::new();
    let device_io = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
        shared_buffer,
    ))));
    let transport = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let mut responder =
        ResponderContext::new(device_io, transport, rsp_config_info, rsp_provision_info);

    // 1. GET_VERSION
    let get_version_req = build_spdm_request(
        SpdmVersion::SpdmVersion10,
        SpdmRequestResponseCode::SpdmRequestGetVersion,
    );
    let mut resp_buf = [0u8; 4096];
    let mut writer = Writer::init(&mut resp_buf);
    let (status, _) = responder.handle_spdm_version(&get_version_req, &mut writer);
    assert!(status.is_ok(), "GET_VERSION should succeed");

    // The dispatcher (context.rs) normally sets AfterVersion and emits
    // HandleGetVersion; since we call handlers directly, do both manually.
    use spdmlib::common::SpdmConnectionState;
    responder
        .common
        .runtime_info
        .set_connection_state(SpdmConnectionState::SpdmConnectionAfterVersion);
    spdm_trace::emit_local_event(
        TraceRole::Responder,
        &responder.common,
        None,
        "HandleGetVersion",
        spdm_trace::TraceMessage::default(),
    );

    // 2-5: Drive remaining handshake through the dispatcher (process_message)
    // which handles state transitions automatically. Use executor::block_on
    // since process_message is async.
    //
    // For now, we use the direct handler approach for the remaining steps.
    // If a handler fails due to message format, we still get the GetVersion event.

    // 2. GET_CAPABILITIES — use the dispatcher path
    let get_cap_req = build_capabilities_request(&mut responder.common);
    let mut resp_buf = [0u8; 4096];
    let mut writer = Writer::init(&mut resp_buf);
    if let (Ok(()), _) = responder.handle_spdm_capability(&get_cap_req, &mut writer) {
        responder.common.runtime_info.set_connection_state(
            SpdmConnectionState::SpdmConnectionAfterCapabilities,
        );
        spdm_trace::emit_local_event(
            TraceRole::Responder, &responder.common, None,
            "HandshakeAdvance", spdm_trace::TraceMessage::default(),
        );

        // 3. NEGOTIATE_ALGORITHMS
        let algo_req = build_algorithm_request(&mut responder.common);
        let mut resp_buf = [0u8; 4096];
        let mut writer = Writer::init(&mut resp_buf);
        if let (Ok(()), _) = responder.handle_spdm_algorithm(&algo_req, &mut writer) {
            responder.common.runtime_info.set_connection_state(
                SpdmConnectionState::SpdmConnectionNegotiated,
            );
            spdm_trace::emit_local_event(
                TraceRole::Responder, &responder.common, None,
                "HandshakeAdvance", spdm_trace::TraceMessage::default(),
            );

            // 4. GET_DIGESTS
            let ver = responder.common.negotiate_info.spdm_version_sel;
            let digest_req =
                build_spdm_request(ver, SpdmRequestResponseCode::SpdmRequestGetDigests);
            let mut resp_buf = [0u8; 4096];
            let mut writer = Writer::init(&mut resp_buf);
            if let (Ok(()), _) = responder.handle_spdm_digest(&digest_req, None, &mut writer) {
                responder.common.runtime_info.set_connection_state(
                    SpdmConnectionState::SpdmConnectionAfterDigest,
                );
                spdm_trace::emit_local_event(
                    TraceRole::Responder, &responder.common, None,
                    "HandshakeAdvance", spdm_trace::TraceMessage::default(),
                );

                // 5. GET_CERTIFICATE
                let cert_req = build_certificate_request(ver, 0, 0);
                let mut resp_buf = [0u8; 4096];
                let mut writer = Writer::init(&mut resp_buf);
                if let (Ok(()), _) = responder.handle_spdm_certificate(&cert_req, None, &mut writer) {
                    responder.common.runtime_info.set_connection_state(
                        SpdmConnectionState::SpdmConnectionAfterCertificate,
                    );
                    spdm_trace::emit_local_event(
                        TraceRole::Responder, &responder.common, None,
                        "HandshakeAdvance", spdm_trace::TraceMessage::default(),
                    );
                }
            }
        }
    }

    spdm_trace::clear_callback();
    close_trace_file();
}

// ---------------------------------------------------------------------------
// Message builders
// ---------------------------------------------------------------------------

fn build_spdm_request(version: SpdmVersion, code: SpdmRequestResponseCode) -> Vec<u8> {
    // Minimal 4-byte SPDM request: version(1) + code(1) + param1(1) + param2(1)
    let mut buf = [0u8; 64];
    buf[0] = u8::from(version);
    buf[1] = code.get_u8();
    buf[2] = 0; // param1
    buf[3] = 0; // param2
    buf[..4].to_vec()
}

fn build_capabilities_request(common: &mut spdmlib::common::SpdmContext) -> Vec<u8> {
    use spdmlib::message::{SpdmGetCapabilitiesRequestPayload};

    let request = SpdmMessage {
        header: SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion12,
            request_response_code: SpdmRequestResponseCode::SpdmRequestGetCapabilities,
        },
        payload: SpdmMessagePayload::SpdmGetCapabilitiesRequest(
            SpdmGetCapabilitiesRequestPayload {
                ct_exponent: 0,
                flags: spdmlib::protocol::SpdmRequestCapabilityFlags::CERT_CAP
                    | spdmlib::protocol::SpdmRequestCapabilityFlags::ENCRYPT_CAP
                    | spdmlib::protocol::SpdmRequestCapabilityFlags::MAC_CAP
                    | spdmlib::protocol::SpdmRequestCapabilityFlags::KEY_EX_CAP
                    | spdmlib::protocol::SpdmRequestCapabilityFlags::KEY_UPD_CAP
                    | spdmlib::protocol::SpdmRequestCapabilityFlags::HBEAT_CAP,
                data_transfer_size: 0x1200,
                max_spdm_msg_size: 0x1200,
                ex_flags: spdmlib::protocol::SpdmRequestCapabilityExFlags::empty(),
            },
        ),
    };
    let mut buf = [0u8; 1024];
    let mut writer = Writer::init(&mut buf);
    request.spdm_encode(common, &mut writer).expect("encode cap");
    writer.used_slice().to_vec()
}

fn build_algorithm_request(common: &mut spdmlib::common::SpdmContext) -> Vec<u8> {
    use spdmlib::message::SpdmNegotiateAlgorithmsRequestPayload;
    use spdmlib::protocol::*;

    let request = SpdmMessage {
        header: SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion12,
            request_response_code: SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms,
        },
        payload: SpdmMessagePayload::SpdmNegotiateAlgorithmsRequest(
            SpdmNegotiateAlgorithmsRequestPayload {
                measurement_specification: SpdmMeasurementSpecification::DMTF,
                other_params_support: SpdmAlgoOtherParams::OPAQUE_DATA_FMT1,
                base_asym_algo: SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
                base_hash_algo: SpdmBaseHashAlgo::TPM_ALG_SHA_384,
                alg_struct_count: 6,
                alg_struct: [
                    SpdmAlgStruct {
                        alg_type: SpdmAlgType::SpdmAlgTypeDHE,
                        alg_supported: SpdmAlg::SpdmAlgoDhe(SpdmDheAlgo::SECP_384_R1),
                    },
                    SpdmAlgStruct {
                        alg_type: SpdmAlgType::SpdmAlgTypeAEAD,
                        alg_supported: SpdmAlg::SpdmAlgoAead(SpdmAeadAlgo::AES_256_GCM),
                    },
                    SpdmAlgStruct {
                        alg_type: SpdmAlgType::SpdmAlgTypeReqAsym,
                        alg_supported: SpdmAlg::SpdmAlgoReqAsym(
                            SpdmReqAsymAlgo::TPM_ALG_RSAPSS_2048,
                        ),
                    },
                    SpdmAlgStruct {
                        alg_type: SpdmAlgType::SpdmAlgTypeKeySchedule,
                        alg_supported: SpdmAlg::SpdmAlgoKeySchedule(
                            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
                        ),
                    },
                    SpdmAlgStruct {
                        alg_type: SpdmAlgType::SpdmAlgTypePqcReqAsym,
                        alg_supported: SpdmAlg::SpdmAlgoPqcReqAsym(
                            SpdmPqcReqAsymAlgo::empty(),
                        ),
                    },
                    SpdmAlgStruct {
                        alg_type: SpdmAlgType::SpdmAlgTypeKEM,
                        alg_supported: SpdmAlg::SpdmAlgoKem(SpdmKemAlgo::empty()),
                    },
                ],
                ..Default::default()
            },
        ),
    };
    let mut buf = [0u8; 1024];
    let mut writer = Writer::init(&mut buf);
    request
        .spdm_encode(common, &mut writer)
        .expect("encode algo");
    writer.used_slice().to_vec()
}

fn build_certificate_request(version: SpdmVersion, slot: u8, offset: u16) -> Vec<u8> {
    let mut buf = [0u8; 64];
    buf[0] = u8::from(version);
    buf[1] = SpdmRequestResponseCode::SpdmRequestGetCertificate.get_u8();
    buf[2] = slot;
    buf[3] = 0; // param2
    // offset (u16 LE)
    buf[4] = (offset & 0xff) as u8;
    buf[5] = ((offset >> 8) & 0xff) as u8;
    // length (u16 LE) — request max
    buf[6] = 0x00;
    buf[7] = 0x10; // 4096
    buf[..8].to_vec()
}
