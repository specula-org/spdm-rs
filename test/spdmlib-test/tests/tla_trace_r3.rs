// Round 3 TLA+ Trace Generation Scenarios for SPDM Protocol
//
// Produces NDJSON traces consumed by spec/Trace.tla for validation.
// Covers: PSK sessions, mutual authentication, key update on PSK.
//
// Extends R2 callback pattern: flat JSON with event name at top level.

use spdmlib::message::key_update::SpdmKeyUpdateOperation;
use spdmlib::protocol::SpdmMeasurementSummaryHashType;
use spdmlib::requester::RequesterContext;
use spdmlib::responder::ResponderContext;
use spdmlib::secret;
use spdmlib::spdm_trace::{self, TraceEvent};
use spdmlib::watchdog::SpdmWatchDog;
use spdmlib_test::common::device_io::{FakeSpdmDeviceIo, FakeSpdmDeviceIoReceve, SharedBuffer};
use spdmlib_test::common::secret_callback::{
    SECRET_ASYM_IMPL_INSTANCE, SECRET_MEASUREMENT_IMPL_INSTANCE, SECRET_PQC_ASYM_IMPL_INSTANCE,
    SECRET_PSK_IMPL_INSTANCE,
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
// NDJSON callback — converts R2/R3 TraceEvent to flat Trace.tla format
// ---------------------------------------------------------------------------

fn r3_callback(event: &TraceEvent) {
    // Only emit R2/R3 events (those with r2 field set)
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

    // R3: Session mode
    if let Some(mode) = r2.session_mode {
        obj.insert("sessionMode".into(), serde_json::json!(mode));
    }

    // R3: PSK cap mode
    if let Some(mode) = r2.psk_cap_mode {
        obj.insert("pskCapMode".into(), serde_json::json!(mode));
    }

    // R3: Mutual auth fields
    if let Some(mode) = r2.mut_auth_mode {
        obj.insert("mutAuthMode".into(), serde_json::json!(mode));
    }
    if let Some(done) = r2.mut_auth_done {
        obj.insert("mutAuthDone".into(), serde_json::json!(done));
    }
    if let Some(state) = r2.encap_state {
        obj.insert("encapState".into(), serde_json::json!(state));
    }

    // R3: Chunking fields
    if let Some(status) = r2.chunk_status {
        obj.insert("chunkStatus".into(), serde_json::json!(status));
    }
    if let Some(seq) = r2.chunk_seq_num {
        obj.insert("chunkSeqNum".into(), serde_json::json!(seq));
    }
    if let Some(handle) = r2.chunk_handle {
        obj.insert("chunkHandle".into(), serde_json::json!(handle));
    }
    if let Some(sid) = r2.chunk_session_id {
        obj.insert("chunkSessionId".into(), serde_json::json!(sid));
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
    secret::psk::register(SECRET_PSK_IMPL_INSTANCE.clone());
    secret::measurement::register(SECRET_MEASUREMENT_IMPL_INSTANCE.clone());
}

fn start_r3_trace(name: &str) {
    open_trace_file(name);
    spdm_trace::reset_shadow_state();
    spdm_trace::register_callback(r3_callback);
}

fn stop_r3_trace() {
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
// Test 1: PSK Session Lifecycle
// GET_VERSION → GET_CAPABILITIES → NEGOTIATE_ALGORITHMS →
// PSK_EXCHANGE → PSK_FINISH → HEARTBEAT → END_SESSION
// ---------------------------------------------------------------------------

#[test]
fn r3_trace_psk_session() {
    start_r3_trace("r3_psk_session.ndjson");
    let future = async {
        let mut requester = setup_requester_responder();
        let mut transcript_vca = None;

        // Negotiate connection (VERSION + CAPABILITIES + ALGORITHMS)
        requester
            .init_connection(&mut transcript_vca)
            .await
            .expect("init connection");

        // PSK session: use_psk=true
        let session_id = requester
            .start_session(
                true, // use PSK
                0,
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
            )
            .await
            .expect("start PSK session");

        // Heartbeat on PSK session
        let _ = requester.send_receive_spdm_heartbeat(session_id).await;

        // End PSK session
        requester
            .send_receive_spdm_end_session(session_id)
            .await
            .expect("end PSK session");
    };
    executor::block_on(future);
    stop_r3_trace();
}

// ---------------------------------------------------------------------------
// Test 2: Cert-Based Session with Key Update (R2 baseline for R3 spec)
// ---------------------------------------------------------------------------

#[test]
fn r3_trace_cert_session_key_update() {
    start_r3_trace("r3_cert_session_key_update.ndjson");
    let future = async {
        let mut requester = setup_requester_responder();
        let mut transcript_vca = None;

        // Negotiate connection
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

        // Cert-based session (includes mutual auth if MUT_AUTH_CAP)
        let session_id = requester
            .start_session(
                false, // cert-based
                0,
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
            )
            .await
            .expect("start cert session");

        // Key update on cert session
        requester
            .send_receive_spdm_key_update(session_id, SpdmKeyUpdateOperation::SpdmUpdateSingleKey)
            .await
            .expect("key update single");

        // End session
        requester
            .send_receive_spdm_end_session(session_id)
            .await
            .expect("end session");
    };
    executor::block_on(future);
    stop_r3_trace();
}

// ---------------------------------------------------------------------------
// Test 3: PSK Session with Key Update
// Verifies key update works on PSK sessions (interaction check)
// ---------------------------------------------------------------------------

#[test]
fn r3_trace_psk_key_update() {
    start_r3_trace("r3_psk_key_update.ndjson");
    let future = async {
        let mut requester = setup_requester_responder();
        let mut transcript_vca = None;

        requester
            .init_connection(&mut transcript_vca)
            .await
            .expect("init connection");

        // PSK session
        let session_id = requester
            .start_session(
                true,
                0,
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
            )
            .await
            .expect("start PSK session");

        // Key update on PSK session
        requester
            .send_receive_spdm_key_update(session_id, SpdmKeyUpdateOperation::SpdmUpdateAllKeys)
            .await
            .expect("key update all");

        requester
            .send_receive_spdm_end_session(session_id)
            .await
            .expect("end session");
    };
    executor::block_on(future);
    stop_r3_trace();
}
