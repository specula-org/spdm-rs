// Copyright (c) 2025
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::device_io::{FakeSpdmDeviceIo, FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::*;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::{create_info, req_create_info, rsp_create_info};
use crate::watchdog_impl_sample::init_watchdog;
use alloc::sync::Arc;
use codec::{Codec, Writer};
use serde_json::{json, Map, Value};
use spin::Mutex;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::{Mutex as StdMutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use alloc::boxed::Box;
use spdmlib::common::session::{SpdmSession, SpdmSessionState};
use spdmlib::config::MAX_SPDM_MSG_SIZE;
use spdmlib::message::key_update::SpdmKeyUpdateOperation;
use spdmlib::message::{SpdmMessageHeader, SpdmRequestResponseCode};
use spdmlib::protocol::{SpdmMeasurementSummaryHashType, SpdmVersion};
use spdmlib::protocol::{
    gen_array_clone, SpdmAeadAlgo, SpdmBaseHashAlgo, SpdmDheAlgo, SpdmDigestStruct, SpdmKemAlgo,
    SpdmKeyScheduleAlgo, SpdmSharedSecretFinalKeyStruct, SPDM_MAX_HASH_SIZE,
    SPDM_MAX_SHARED_SECRET_SIZE,
};
use spdmlib::requester::RequesterContext;
use spdmlib::spdm_trace::{
    self, TraceErrorKind, TraceEvent, TraceKeyState, TraceKeyUpdateOp, TraceMessage, TracePeerState,
    TraceTranscriptPhase,
};
use spdmlib::{responder, secret};

extern crate alloc;

static TRACE_WRITER: OnceLock<StdMutex<Option<BufWriter<File>>>> = OnceLock::new();

fn writer() -> &'static StdMutex<Option<BufWriter<File>>> {
    TRACE_WRITER.get_or_init(|| StdMutex::new(None))
}

fn start_trace(name: &str) {
    let trace_dir = std::env::var("SPECULA_TRACE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::current_dir()
                .expect("current dir")
                .join("../../traces")
        });
    fs::create_dir_all(&trace_dir).expect("failed to create trace dir");
    let file = File::create(trace_dir.join(format!("{name}.ndjson"))).expect("create trace file");
    {
        let mut guard = writer().lock().expect("lock trace writer");
        *guard = Some(BufWriter::new(file));
    }
    write_json_line(&json!({
        "tag": "config",
        "ts": now_nanos(),
        "config": {
            "servers": ["requester", "responder"],
            "handshakeInClear": false
        }
    }));
    spdm_trace::reset_shadow_state();
    spdm_trace::register_callback(trace_callback);
}

fn stop_trace() {
    spdm_trace::clear_callback();
    let mut guard = writer().lock().expect("lock trace writer");
    if let Some(writer) = guard.as_mut() {
        writer.flush().expect("flush trace");
    }
    *guard = None;
}

fn write_json_line(value: &Value) {
    let mut guard = writer().lock().expect("lock trace writer");
    let writer = guard.as_mut().expect("trace writer not initialized");
    serde_json::to_writer(&mut *writer, value).expect("write trace json");
    writer.write_all(b"\n").expect("write newline");
    writer.flush().expect("flush trace line");
}

fn trace_callback(event: &TraceEvent) {
    write_json_line(&json!({
        "tag": "trace",
        "ts": now_nanos(),
        "event": {
            "name": event.name,
            "nid": event.nid,
            "state": state_json(&event.state.requester, &event.state.responder, event.msg, event),
            "msg": msg_json(&event.msg)
        }
    }));
}

fn state_json(
    requester: &Option<TracePeerState>,
    responder: &Option<TracePeerState>,
    _msg: TraceMessage,
    event: &TraceEvent,
) -> Value {
    let mut state = Map::new();
    if let Some(peer) = requester {
        state.insert("requester".into(), peer_json(*peer));
    }
    if let Some(peer) = responder {
        state.insert("responder".into(), peer_json(*peer));
    }
    if let Some(req_key_state) = event.state.req_key_state {
        state.insert("reqKeyState".into(), json!(key_state_name(req_key_state)));
    }
    if let Some(rsp_key_state) = event.state.rsp_key_state {
        state.insert("rspKeyState".into(), json!(key_state_name(rsp_key_state)));
    }
    if let Some(req_backup_valid) = event.state.req_backup_valid {
        state.insert("reqBackupValid".into(), json!(req_backup_valid));
    }
    if let Some(rsp_backup_valid) = event.state.rsp_backup_valid {
        state.insert("rspBackupValid".into(), json!(rsp_backup_valid));
    }
    Value::Object(state)
}

fn peer_json(peer: TracePeerState) -> Value {
    let mut obj = Map::new();
    if let Some(connection_state) = peer.connection_state {
        obj.insert(
            "connectionState".into(),
            json!(connection_state_name(connection_state)),
        );
    }
    if let Some(session_state) = peer.session_state {
        obj.insert("sessionState".into(), json!(session_state_name(session_state)));
    }
    if let Some(transcript_phase) = peer.transcript_phase {
        obj.insert(
            "transcriptPhase".into(),
            json!(transcript_phase_name(transcript_phase)),
        );
    }
    Value::Object(obj)
}

fn msg_json(msg: &TraceMessage) -> Value {
    let mut obj = Map::new();
    if let Some(version) = msg.version {
        obj.insert("version".into(), json!(version));
    }
    if let Some(slot) = msg.slot {
        obj.insert("slot".into(), json!(slot_name(slot)));
    }
    if let Some(op) = msg.op {
        obj.insert("op".into(), json!(key_update_op_name(op)));
    }
    if let Some(slot_mask) = msg.slot_mask {
        obj.insert("slotMask".into(), json!(slot_mask_names(slot_mask)));
    }
    if let Some(error) = msg.error {
        obj.insert("error".into(), json!(error_name(error)));
    }
    Value::Object(obj)
}

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_nanos()
}

fn connection_state_name(state: spdmlib::common::SpdmConnectionState) -> &'static str {
    match state {
        spdmlib::common::SpdmConnectionState::SpdmConnectionNotStarted => "ConnNotStarted",
        spdmlib::common::SpdmConnectionState::SpdmConnectionAfterVersion => "ConnAfterVersion",
        spdmlib::common::SpdmConnectionState::SpdmConnectionNegotiated => "ConnNegotiated",
        spdmlib::common::SpdmConnectionState::SpdmConnectionAfterCertificate => {
            "ConnAfterCertificate"
        }
        spdmlib::common::SpdmConnectionState::SpdmConnectionAuthenticated => {
            "ConnAuthenticated"
        }
        _ => "ConnNotStarted",
    }
}

fn session_state_name(state: spdmlib::common::session::SpdmSessionState) -> &'static str {
    match state {
        spdmlib::common::session::SpdmSessionState::SpdmSessionNotStarted => "SessNotStarted",
        spdmlib::common::session::SpdmSessionState::SpdmSessionHandshaking => "SessHandshaking",
        spdmlib::common::session::SpdmSessionState::SpdmSessionEstablished => "SessEstablished",
        _ => "SessNotStarted",
    }
}

fn transcript_phase_name(phase: TraceTranscriptPhase) -> &'static str {
    match phase {
        TraceTranscriptPhase::Empty => "TranscriptEmpty",
        TraceTranscriptPhase::A => "TranscriptA",
        TraceTranscriptPhase::B => "TranscriptB",
        TraceTranscriptPhase::C => "TranscriptC",
        TraceTranscriptPhase::K => "TranscriptK",
        TraceTranscriptPhase::Established => "TranscriptEstablished",
    }
}

fn key_state_name(state: TraceKeyState) -> &'static str {
    match state {
        TraceKeyState::Old => "KeyOld",
        TraceKeyState::New => "KeyNew",
    }
}

fn key_update_op_name(op: TraceKeyUpdateOp) -> &'static str {
    match op {
        TraceKeyUpdateOp::UpdateSingle => "OpUpdateSingle",
        TraceKeyUpdateOp::UpdateAll => "OpUpdateAll",
        TraceKeyUpdateOp::VerifyNewKey => "OpVerifyNewKey",
    }
}

fn error_name(error: TraceErrorKind) -> &'static str {
    match error {
        TraceErrorKind::Unexpected => "ErrUnexpected",
        TraceErrorKind::Unsupported => "ErrUnsupported",
        TraceErrorKind::Invalid => "ErrInvalid",
    }
}

fn slot_name(slot: u8) -> String {
    format!("slot{slot}")
}

fn slot_mask_names(mask: u8) -> Vec<String> {
    let mut names = Vec::new();
    for slot in 0..8 {
        if mask & (1 << slot) != 0 {
            names.push(slot_name(slot));
        }
    }
    names
}

fn setup_requester_responder() -> RequesterContext {
    secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    secret::pqc_asym_sign::register(SECRET_PQC_ASYM_IMPL_INSTANCE.clone());
    init_watchdog();

    let (rsp_config_info, rsp_provision_info) = rsp_create_info();
    let (req_config_info, req_provision_info) = req_create_info();

    let shared_buffer = SharedBuffer::new();
    let device_io_responder = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
        shared_buffer,
    ))));
    let transport_encap_responder = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let responder_context = responder::ResponderContext::new(
        device_io_responder,
        transport_encap_responder,
        rsp_config_info,
        rsp_provision_info,
    );

    let shared_buffer = SharedBuffer::new();
    let device_io_requester = Arc::new(Mutex::new(FakeSpdmDeviceIo::new(
        Arc::new(shared_buffer),
        Arc::new(Mutex::new(responder_context)),
    )));
    let transport_encap_requester = Arc::new(Mutex::new(PciDoeTransportEncap {}));

    RequesterContext::new(
        device_io_requester,
        transport_encap_requester,
        req_config_info,
        req_provision_info,
    )
}

fn setup_established_key_update_requester() -> RequesterContext {
    secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    secret::pqc_asym_sign::register(SECRET_PQC_ASYM_IMPL_INSTANCE.clone());

    let (rsp_config_info, rsp_provision_info) = create_info();
    let (req_config_info, req_provision_info) = create_info();

    let shared_buffer = SharedBuffer::new();
    let device_io_responder = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
        shared_buffer,
    ))));
    let transport_encap_responder = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let mut responder = responder::ResponderContext::new(
        device_io_responder,
        transport_encap_responder,
        rsp_config_info,
        rsp_provision_info,
    );

    let rsp_session_id = 0xFFFEu16;
    let session_id = (0xffu32 << 16) + rsp_session_id as u32;
    responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    responder.common.session = gen_array_clone(SpdmSession::new(), 4);
    responder.common.session[0].setup(session_id).expect("setup responder session");
    responder.common.session[0].set_crypto_param(
        SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        SpdmDheAlgo::SECP_384_R1,
        SpdmKemAlgo::empty(),
        SpdmAeadAlgo::AES_256_GCM,
        SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
    );
    responder.common.session[0].set_session_state(SpdmSessionState::SpdmSessionEstablished);
    let shared_secret = SpdmSharedSecretFinalKeyStruct {
        data_size: 48,
        data: Box::new([0; SPDM_MAX_SHARED_SECRET_SIZE]),
    };
    let _ = responder.common.session[0].set_shared_secret(SpdmVersion::SpdmVersion12, shared_secret);
    let _ = responder.common.session[0].generate_handshake_secret(
        SpdmVersion::SpdmVersion12,
        &SpdmDigestStruct {
            data_size: 48,
            data: Box::new([0; SPDM_MAX_HASH_SIZE]),
        },
    );
    let _ = responder.common.session[0].generate_data_secret(
        SpdmVersion::SpdmVersion12,
        &SpdmDigestStruct {
            data_size: 48,
            data: Box::new([0; SPDM_MAX_HASH_SIZE]),
        },
    );

    let shared_buffer = SharedBuffer::new();
    let device_io_requester = Arc::new(Mutex::new(FakeSpdmDeviceIo::new(
        Arc::new(shared_buffer),
        Arc::new(Mutex::new(responder)),
    )));
    let transport_encap_requester = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let mut requester = RequesterContext::new(
        device_io_requester,
        transport_encap_requester,
        req_config_info,
        req_provision_info,
    );

    requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    requester.common.session = gen_array_clone(SpdmSession::new(), 4);
    requester.common.session[0].setup(session_id).expect("setup requester session");
    requester.common.session[0].set_crypto_param(
        SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        SpdmDheAlgo::SECP_384_R1,
        SpdmKemAlgo::empty(),
        SpdmAeadAlgo::AES_256_GCM,
        SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
    );
    requester.common.session[0].set_session_state(SpdmSessionState::SpdmSessionEstablished);
    let shared_secret = SpdmSharedSecretFinalKeyStruct {
        data_size: 48,
        data: Box::new([0; SPDM_MAX_SHARED_SECRET_SIZE]),
    };
    let _ = requester.common.session[0].set_shared_secret(SpdmVersion::SpdmVersion12, shared_secret);
    let _ = requester.common.session[0].generate_handshake_secret(
        SpdmVersion::SpdmVersion12,
        &SpdmDigestStruct {
            data_size: 48,
            data: Box::new([0; SPDM_MAX_HASH_SIZE]),
        },
    );
    let _ = requester.common.session[0].generate_data_secret(
        SpdmVersion::SpdmVersion12,
        &SpdmDigestStruct {
            data_size: 48,
            data: Box::new([0; SPDM_MAX_HASH_SIZE]),
        },
    );

    requester
}

#[test]
fn trace_version_certificate_challenge() {
    start_trace("version_certificate_challenge");
    let future = async {
        let mut requester = setup_requester_responder();
        let mut transcript_vca = None;
        requester
            .init_connection(&mut transcript_vca)
            .await
            .expect("init connection");
        requester
            .send_receive_spdm_digest(None)
            .await
            .expect("digests");
        requester
            .send_receive_spdm_certificate(None, 0)
            .await
            .expect("certificate");
        requester
            .send_receive_spdm_challenge(
                0,
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
                None,
            )
            .await
            .expect("challenge");
    };
    executor::block_on(future);
    stop_trace();
}

#[test]
fn trace_session_key_update() {
    start_trace("session_key_update");
    let future = async {
        let mut requester = setup_established_key_update_requester();
        let session_id = (0xffu32 << 16) + 0xFFFEu16 as u32;
        requester
            .send_receive_spdm_key_update(session_id, SpdmKeyUpdateOperation::SpdmUpdateAllKeys)
            .await
            .expect("key update");
    };
    executor::block_on(future);
    stop_trace();
}

#[test]
fn trace_unexpected_request() {
    start_trace("unexpected_request");
    let (config_info, provision_info) = create_info();
    let shared_buffer = SharedBuffer::new();
    let device_io_responder = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
        shared_buffer,
    ))));
    let transport_encap_responder = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let mut responder = responder::ResponderContext::new(
        device_io_responder,
        transport_encap_responder,
        config_info,
        provision_info,
    );
    responder.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;

    let mut request = [0u8; MAX_SPDM_MSG_SIZE];
    let mut request_writer = Writer::init(&mut request);
    let header = SpdmMessageHeader {
        version: SpdmVersion::SpdmVersion12,
        request_response_code: SpdmRequestResponseCode::SpdmRequestKeyUpdate,
    };
    header.encode(&mut request_writer).expect("encode header");
    let mut response = [0u8; MAX_SPDM_MSG_SIZE];
    let mut response_writer = Writer::init(&mut response);
    let _ = responder.dispatch_message(request_writer.used_slice(), &mut response_writer);
    stop_trace();
}
