// Round 2 TLA+ Trace Generation Scenarios for SPDM Protocol
//
// Produces NDJSON traces consumed by spec/Trace.tla for validation.
// Covers: capabilities, algorithms, multi-session, end_session, GET_VERSION reset.

use spdmlib::message::key_update::SpdmKeyUpdateOperation;
use spdmlib::protocol::SpdmMeasurementSummaryHashType;
use spdmlib::requester::RequesterContext;
use spdmlib::responder::ResponderContext;
use spdmlib::secret;
use spdmlib::spdm_trace::{self, TraceEvent};
use spdmlib::watchdog::SpdmWatchDog;
use spdmlib_test::common::device_io::{FakeSpdmDeviceIo, FakeSpdmDeviceIoReceve, SharedBuffer};
use spdmlib_test::common::secret_callback::{
    SECRET_ASYM_IMPL_INSTANCE, SECRET_PQC_ASYM_IMPL_INSTANCE,
};
use spdmlib_test::common::transport::PciDoeTransportEncap;
use spdmlib_test::common::util::{req_create_info, rsp_create_info};
use spin::Mutex;
use std::io::Write;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Global trace file handle
// ---------------------------------------------------------------------------

static TRACE_FILE: std::sync::Mutex<Option<std::fs::File>> = std::sync::Mutex::new(None);

fn open_trace_file(name: &str) {
    let traces_dir = std::env::var("SPECULA_TRACE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../traces")
        });
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

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_nanos()
}

// ---------------------------------------------------------------------------
// NDJSON callback — converts R2 TraceEvent to flat Trace.tla format
// ---------------------------------------------------------------------------

fn r2_callback(event: &TraceEvent) {
    // Only emit R2 events (those with r2 field set)
    let r2 = match &event.r2 {
        Some(r2) => r2,
        None => return,
    };

    let ts = now_nanos();
    let mut obj = serde_json::Map::new();
    obj.insert("event".into(), serde_json::json!(event.name));
    obj.insert("role".into(), serde_json::json!(event.nid));
    obj.insert("timestamp".into(), serde_json::json!(ts));

    // Connection states
    if let Some(cs) = r2.req_connection_state {
        obj.insert("reqConnectionState".into(), serde_json::json!(spdm_trace::connection_state_str(cs)));
    }
    if let Some(cs) = r2.rsp_connection_state {
        obj.insert("rspConnectionState".into(), serde_json::json!(spdm_trace::connection_state_str(cs)));
    }

    // Negotiated version
    if let Some(v) = r2.negotiated_version {
        obj.insert("negotiatedVersion".into(), serde_json::json!(v));
    }

    // Capability flags (message payload)
    if let Some(ref caps) = r2.req_caps {
        obj.insert("reqCaps".into(), serde_json::json!(caps));
    }
    if let Some(ref caps) = r2.rsp_caps {
        obj.insert("rspCaps".into(), serde_json::json!(caps));
    }

    // Stored capability flags
    if let Some(ref caps) = r2.req_capabilities {
        obj.insert("reqCapabilities".into(), serde_json::json!(caps));
    }
    if let Some(ref caps) = r2.rsp_capabilities {
        obj.insert("rspCapabilities".into(), serde_json::json!(caps));
    }

    // Algorithm fields
    if let Some(ref algos) = r2.proposed {
        obj.insert("proposed".into(), serde_json::json!(algos));
    }
    if let Some(ref algos) = r2.rsp_supported {
        obj.insert("rspSupported".into(), serde_json::json!(algos));
    }
    if let Some(algo) = r2.negotiated_algo {
        obj.insert("negotiatedAlgo".into(), serde_json::json!(algo));
    }

    // Session fields
    if let Some(sid) = r2.session_id {
        obj.insert("sessionId".into(), serde_json::json!(sid));
    }
    if let Some(ss) = r2.session_state {
        obj.insert("sessionState".into(), serde_json::json!(ss));
    }
    if let Some(slot) = r2.session_slot {
        obj.insert("sessionSlot".into(), serde_json::json!(slot));
    }

    // Backup valid
    if let Some(bv) = r2.req_backup_valid {
        obj.insert("reqBackupValid".into(), serde_json::json!(bv));
    }
    if let Some(bv) = r2.rsp_backup_valid {
        obj.insert("rspBackupValid".into(), serde_json::json!(bv));
    }

    // Key update operation
    if let Some(op) = r2.op {
        obj.insert("op".into(), serde_json::json!(op));
    }

    // Error
    if let Some(err) = r2.error {
        obj.insert("error".into(), serde_json::json!(err));
    }

    let line = serde_json::Value::Object(obj);
    let mut guard = TRACE_FILE.lock().unwrap();
    if let Some(ref mut f) = *guard {
        serde_json::to_writer(&mut *f, &line).ok();
        writeln!(f).ok();
        f.flush().ok();
    }
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn register_crypto() {
    secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    secret::pqc_asym_sign::register(SECRET_PQC_ASYM_IMPL_INSTANCE.clone());
}

fn start_r2_trace(name: &str) {
    open_trace_file(name);
    spdm_trace::reset_shadow_state();
    spdm_trace::register_callback(r2_callback);
}

fn stop_r2_trace() {
    spdm_trace::clear_callback();
    close_trace_file();
}

fn init_watchdog() {
    spdmlib::watchdog::register(SpdmWatchDog {
        start_watchdog_cb: |_session_id, _seconds| {},
        stop_watchdog_cb: |_session_id| {},
        reset_watchdog_cb: |_session_id| {},
    });
}

fn setup_requester_responder() -> RequesterContext {
    register_crypto();
    init_watchdog();

    let (mut rsp_config_info, rsp_provision_info) = rsp_create_info();
    let (mut req_config_info, req_provision_info) = req_create_info();

    // Restrict to SPDM 1.1 and 1.2 to match Trace.tla model
    use spdmlib::protocol::SpdmVersion;
    req_config_info.spdm_version = [
        Some(SpdmVersion::SpdmVersion11),
        Some(SpdmVersion::SpdmVersion12),
        None,
        None,
        None,
    ];
    rsp_config_info.spdm_version = [
        Some(SpdmVersion::SpdmVersion11),
        Some(SpdmVersion::SpdmVersion12),
        None,
        None,
        None,
    ];

    let shared_buffer = SharedBuffer::new();
    let device_io_responder = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
        shared_buffer,
    ))));
    let transport_encap_responder = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let responder_context = ResponderContext::new(
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

// ---------------------------------------------------------------------------
// Test: Basic Session Lifecycle (GET_VERSION → FINISH → END_SESSION)
// ---------------------------------------------------------------------------

#[test]
fn r2_trace_basic_session_lifecycle() {
    start_r2_trace("r2_basic_session_lifecycle.ndjson");
    let future = async {
        let mut requester = setup_requester_responder();
        let mut transcript_vca = None;

        // GET_VERSION + GET_CAPABILITIES + NEGOTIATE_ALGORITHMS
        requester
            .init_connection(&mut transcript_vca)
            .await
            .expect("init connection");

        // GET_DIGESTS + GET_CERTIFICATE
        requester
            .send_receive_spdm_digest(None)
            .await
            .expect("digests");
        requester
            .send_receive_spdm_certificate(None, 0)
            .await
            .expect("certificate");

        // KEY_EXCHANGE + FINISH → session established
        let result = requester
            .start_session(
                false,
                0,
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
            )
            .await;
        let session_id = result.expect("start session");

        // HEARTBEAT
        let _ = requester.send_receive_spdm_heartbeat(session_id).await;

        // END_SESSION
        requester
            .send_receive_spdm_end_session(session_id)
            .await
            .expect("end session");
    };
    executor::block_on(future);
    stop_r2_trace();
}

// ---------------------------------------------------------------------------
// Test: Multi-Session (two concurrent sessions)
// ---------------------------------------------------------------------------

#[test]
fn r2_trace_multi_session() {
    start_r2_trace("r2_multi_session.ndjson");
    let future = async {
        let mut requester = setup_requester_responder();
        let mut transcript_vca = None;

        // Negotiate connection
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

        // Session 1
        let session_id_1 = requester
            .start_session(
                false,
                0,
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
            )
            .await
            .expect("start session 1");

        // Session 2
        let session_id_2 = requester
            .start_session(
                false,
                0,
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
            )
            .await
            .expect("start session 2");

        // Heartbeat on session 1
        let _ = requester.send_receive_spdm_heartbeat(session_id_1).await;

        // End session 1
        requester
            .send_receive_spdm_end_session(session_id_1)
            .await
            .expect("end session 1");

        // Session 2 should still work — heartbeat
        let _ = requester.send_receive_spdm_heartbeat(session_id_2).await;

        // End session 2
        requester
            .send_receive_spdm_end_session(session_id_2)
            .await
            .expect("end session 2");
    };
    executor::block_on(future);
    stop_r2_trace();
}

// ---------------------------------------------------------------------------
// Test: GET_VERSION Reset (establish session, then GET_VERSION destroys it)
// ---------------------------------------------------------------------------

#[test]
fn r2_trace_version_reset() {
    start_r2_trace("r2_version_reset.ndjson");
    let future = async {
        let mut requester = setup_requester_responder();
        let mut transcript_vca = None;

        // First connection: full handshake
        requester
            .init_connection(&mut transcript_vca)
            .await
            .expect("init connection 1");
        requester
            .send_receive_spdm_digest(None)
            .await
            .expect("digests");
        requester
            .send_receive_spdm_certificate(None, 0)
            .await
            .expect("certificate");
        let _session_id = requester
            .start_session(
                false,
                0,
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
            )
            .await
            .expect("start session");

        // Re-negotiate: GET_VERSION resets everything including sessions
        // The requester's init_connection starts with GET_VERSION which
        // triggers reset_context() on the responder side.
        let mut transcript_vca2 = None;
        requester
            .init_connection(&mut transcript_vca2)
            .await
            .expect("init connection 2 (resets sessions)");
    };
    executor::block_on(future);
    stop_r2_trace();
}

// ---------------------------------------------------------------------------
// Test: Key Update in Session
// ---------------------------------------------------------------------------

#[test]
fn r2_trace_key_update() {
    start_r2_trace("r2_key_update.ndjson");
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
        let session_id = requester
            .start_session(
                false,
                0,
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
            )
            .await
            .expect("start session");

        // Key update: UpdateSingle + VerifyNewKey
        requester
            .send_receive_spdm_key_update(session_id, SpdmKeyUpdateOperation::SpdmUpdateSingleKey)
            .await
            .expect("key update single");

        requester
            .send_receive_spdm_end_session(session_id)
            .await
            .expect("end session");
    };
    executor::block_on(future);
    stop_r2_trace();
}
