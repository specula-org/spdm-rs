// Copyright (c) 2025
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::session::{SpdmSession, SpdmSessionState};
use crate::common::{SpdmConnectionState, SpdmContext};
use spin::Mutex;

extern crate alloc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceRole {
    Requester,
    Responder,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceTranscriptPhase {
    Empty,
    A,
    B,
    C,
    K,
    Established,
}

/// Key generation state per-side per-direction.
/// 0 = no key, 1 = initial (post-FINISH), 2+ = after key updates.
#[derive(Clone, Copy, Debug, Default)]
pub struct TraceKeyGens {
    pub rq_req: u32,
    pub rq_resp: u32,
    pub rs_req: u32,
    pub rs_resp: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceKeyUpdateOp {
    UpdateSingle,
    UpdateAll,
    VerifyNewKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceErrorKind {
    Unexpected,
    Unsupported,
    Invalid,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TracePeerState {
    pub connection_state: Option<SpdmConnectionState>,
    pub session_state: Option<SpdmSessionState>,
    pub transcript_phase: Option<TraceTranscriptPhase>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TraceStateSnapshot {
    pub requester: Option<TracePeerState>,
    pub responder: Option<TracePeerState>,
    pub key_gens: Option<TraceKeyGens>,
    pub req_backup_valid: Option<bool>,
    pub rsp_backup_valid: Option<bool>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TraceMessage {
    pub version: Option<u8>,
    pub slot: Option<u8>,
    pub op: Option<TraceKeyUpdateOp>,
    pub slot_mask: Option<u8>,
    pub error: Option<TraceErrorKind>,
    pub hmac_ok: Option<bool>,
    pub data_secret_ok: Option<bool>,
    pub req_ok: Option<bool>,
    pub resp_ok: Option<bool>,
}

#[derive(Clone, Debug)]
pub struct TraceEvent {
    pub name: &'static str,
    pub nid: &'static str,
    pub state: TraceStateSnapshot,
    pub msg: TraceMessage,
    /// Round 2 extension fields (capabilities, algorithms, session lifecycle).
    /// None for Round 1 events.
    pub r2: Option<TraceR2Fields>,
}

#[derive(Clone, Copy, Debug)]
struct TraceRuntime {
    callback: Option<fn(&TraceEvent)>,
    requester_connection: SpdmConnectionState,
    requester_transcript: TraceTranscriptPhase,
    responder_transcript: TraceTranscriptPhase,
    key_gens: TraceKeyGens,
    requester_last: TracePeerState,
    responder_last: TracePeerState,
}

impl Default for TraceRuntime {
    fn default() -> Self {
        Self {
            callback: None,
            requester_connection: SpdmConnectionState::SpdmConnectionNotStarted,
            requester_transcript: TraceTranscriptPhase::Empty,
            responder_transcript: TraceTranscriptPhase::Empty,
            key_gens: TraceKeyGens::default(),
            requester_last: TracePeerState::default(),
            responder_last: TracePeerState::default(),
        }
    }
}

static TRACE_RUNTIME: Mutex<TraceRuntime> = Mutex::new(TraceRuntime {
    callback: None,
    requester_connection: SpdmConnectionState::SpdmConnectionNotStarted,
    requester_transcript: TraceTranscriptPhase::Empty,
    responder_transcript: TraceTranscriptPhase::Empty,
    key_gens: TraceKeyGens {
        rq_req: 0,
        rq_resp: 0,
        rs_req: 0,
        rs_resp: 0,
    },
    requester_last: TracePeerState {
        connection_state: None,
        session_state: None,
        transcript_phase: None,
    },
    responder_last: TracePeerState {
        connection_state: None,
        session_state: None,
        transcript_phase: None,
    },
});

pub fn register_callback(callback: fn(&TraceEvent)) {
    TRACE_RUNTIME.lock().callback = Some(callback);
}

pub fn clear_callback() {
    TRACE_RUNTIME.lock().callback = None;
}

pub fn reset_shadow_state() {
    let callback = TRACE_RUNTIME.lock().callback;
    *TRACE_RUNTIME.lock() = TraceRuntime {
        callback,
        ..TraceRuntime::default()
    };
}

pub fn note_transcript(role: TraceRole, phase: TraceTranscriptPhase) {
    let mut runtime = TRACE_RUNTIME.lock();
    match role {
        TraceRole::Requester => runtime.requester_transcript = phase,
        TraceRole::Responder => runtime.responder_transcript = phase,
    }
}

pub fn note_connection(role: TraceRole, connection_state: SpdmConnectionState) {
    if role == TraceRole::Requester {
        TRACE_RUNTIME.lock().requester_connection = connection_state;
    }
}

/// Responder completed key update. Increment responder-side key gens.
pub fn note_key_update_response(op: TraceKeyUpdateOp, req_ok: bool, resp_ok: bool) {
    let mut runtime = TRACE_RUNTIME.lock();
    match op {
        TraceKeyUpdateOp::UpdateSingle => {
            if req_ok { runtime.key_gens.rs_req += 1; }
        }
        TraceKeyUpdateOp::UpdateAll => {
            if req_ok { runtime.key_gens.rs_req += 1; }
            if resp_ok { runtime.key_gens.rs_resp += 1; }
        }
        TraceKeyUpdateOp::VerifyNewKey => {}
    }
}

/// Requester received KEY_UPDATE_ACK. Increment requester-side key gens.
pub fn note_key_update_ack(op: TraceKeyUpdateOp) {
    let mut runtime = TRACE_RUNTIME.lock();
    match op {
        TraceKeyUpdateOp::UpdateSingle => {
            runtime.key_gens.rq_req += 1;
        }
        TraceKeyUpdateOp::UpdateAll => {
            runtime.key_gens.rq_req += 1;
            runtime.key_gens.rq_resp += 1;
        }
        TraceKeyUpdateOp::VerifyNewKey => {}
    }
}

pub fn note_key_update_rollback(_req_backup_valid: bool, _rsp_backup_valid: bool) {
    // Rollback doesn't change gen counters — the backup was the previous gen,
    // and on rollback the active key reverts to backup (gen stays the same).
}

/// Data secret generated successfully after FINISH. Set initial key gen = 1.
pub fn note_data_secret_generated(role: TraceRole) {
    let mut runtime = TRACE_RUNTIME.lock();
    match role {
        TraceRole::Requester => {
            runtime.key_gens.rq_req = 1;
            runtime.key_gens.rq_resp = 1;
        }
        TraceRole::Responder => {
            runtime.key_gens.rs_req = 1;
            runtime.key_gens.rs_resp = 1;
        }
    }
}

/// GetVersion resets all state including keys.
pub fn note_reset() {
    let mut runtime = TRACE_RUNTIME.lock();
    runtime.key_gens = TraceKeyGens::default();
    runtime.requester_transcript = TraceTranscriptPhase::Empty;
    runtime.responder_transcript = TraceTranscriptPhase::Empty;
    runtime.requester_connection = SpdmConnectionState::SpdmConnectionNotStarted;
}

pub fn observe_local_state(role: TraceRole, context: &SpdmContext, session_id: Option<u32>) {
    let peer = local_peer_state(role, context, session_id);
    let mut runtime = TRACE_RUNTIME.lock();
    match role {
        TraceRole::Requester => runtime.requester_last = peer,
        TraceRole::Responder => runtime.responder_last = peer,
    }
}

pub fn emit_local_event(
    role: TraceRole,
    context: &SpdmContext,
    session_id: Option<u32>,
    name: &'static str,
    msg: TraceMessage,
) {
    emit_event(role, context, session_id, name, msg, false, false);
}

pub fn emit_key_event(
    role: TraceRole,
    context: &SpdmContext,
    session_id: u32,
    name: &'static str,
    msg: TraceMessage,
) {
    emit_event(role, context, Some(session_id), name, msg, false, true);
}

pub fn emit_finish_event(
    role: TraceRole,
    context: &SpdmContext,
    session_id: u32,
    name: &'static str,
) {
    emit_event(
        role,
        context,
        Some(session_id),
        name,
        TraceMessage::default(),
        true,
        false,
    );
}

fn emit_event(
    role: TraceRole,
    context: &SpdmContext,
    session_id: Option<u32>,
    name: &'static str,
    msg: TraceMessage,
    include_remote: bool,
    include_key_state: bool,
) {
    let local = local_peer_state(role, context, session_id);

    let (callback, remote, key_gens) = {
        let mut runtime = TRACE_RUNTIME.lock();
        match role {
            TraceRole::Requester => runtime.requester_last = local,
            TraceRole::Responder => runtime.responder_last = local,
        }

        let remote = if include_remote {
            match role {
                TraceRole::Requester => Some(runtime.responder_last),
                TraceRole::Responder => Some(runtime.requester_last),
            }
        } else {
            None
        };

        (
            runtime.callback,
            remote,
            runtime.key_gens,
        )
    };

    if let Some(callback) = callback {
        let mut state = TraceStateSnapshot::default();
        match role {
            TraceRole::Requester => {
                state.requester = Some(local);
                if include_remote {
                    state.responder = remote;
                }
            }
            TraceRole::Responder => {
                state.responder = Some(local);
                if include_remote {
                    state.requester = remote;
                }
            }
        }

        if include_key_state {
            let (req_backup_valid, rsp_backup_valid) = session_id
                .and_then(|id| context.get_immutable_session_via_id(id))
                .map(|session| {
                    (
                        session.get_requester_backup_valid(),
                        session.get_responder_backup_valid(),
                    )
                })
                .unwrap_or((false, false));
            state.key_gens = Some(key_gens);
            state.req_backup_valid = Some(req_backup_valid);
            state.rsp_backup_valid = Some(rsp_backup_valid);
        }

        let event = TraceEvent {
            name,
            nid: role_name(role),
            state,
            msg,
            r2: None,
        };
        callback(&event);
    }
}

fn local_peer_state(role: TraceRole, context: &SpdmContext, session_id: Option<u32>) -> TracePeerState {
    let transcript = {
        let runtime = TRACE_RUNTIME.lock();
        (
            match role {
                TraceRole::Requester => runtime.requester_connection,
                TraceRole::Responder => context.runtime_info.get_connection_state(),
            },
            match role {
                TraceRole::Requester => runtime.requester_transcript,
                TraceRole::Responder => runtime.responder_transcript,
            },
        )
    };

    TracePeerState {
        connection_state: Some(transcript.0),
        session_state: Some(
            active_session(context, session_id)
                .map(SpdmSession::get_session_state)
                .unwrap_or(SpdmSessionState::SpdmSessionNotStarted),
        ),
        transcript_phase: Some(transcript.1),
    }
}

fn active_session(context: &SpdmContext, session_id: Option<u32>) -> Option<&SpdmSession> {
    if let Some(session_id) = session_id.or(context.runtime_info.get_last_session_id()) {
        context.get_immutable_session_via_id(session_id)
    } else {
        None
    }
}

fn role_name(role: TraceRole) -> &'static str {
    match role {
        TraceRole::Requester => "requester",
        TraceRole::Responder => "responder",
    }
}

// ============================================================================
// Round 2 trace extension — capabilities, algorithms, session lifecycle
// ============================================================================

/// Round 2/3 event fields for capabilities, algorithms, session lifecycle,
/// PSK sessions, mutual auth, and chunking.
/// All fields are optional; only populated fields are emitted.
#[derive(Clone, Debug, Default)]
pub struct TraceR2Fields {
    pub req_connection_state: Option<SpdmConnectionState>,
    pub rsp_connection_state: Option<SpdmConnectionState>,
    pub negotiated_version: Option<u8>,
    pub req_caps: Option<alloc::vec::Vec<&'static str>>,
    pub rsp_caps: Option<alloc::vec::Vec<&'static str>>,
    pub req_capabilities: Option<alloc::vec::Vec<&'static str>>,
    pub rsp_capabilities: Option<alloc::vec::Vec<&'static str>>,
    pub proposed: Option<alloc::vec::Vec<&'static str>>,
    pub rsp_supported: Option<alloc::vec::Vec<&'static str>>,
    pub negotiated_algo: Option<&'static str>,
    pub session_id: Option<u32>,
    pub session_state: Option<&'static str>,
    pub session_slot: Option<u32>,
    pub req_backup_valid: Option<bool>,
    pub rsp_backup_valid: Option<bool>,
    pub op: Option<&'static str>,
    pub error: Option<&'static str>,
    // Round 3: PSK session fields
    pub session_mode: Option<&'static str>,
    pub psk_cap_mode: Option<&'static str>,
    // Round 3: Mutual auth fields
    pub mut_auth_mode: Option<&'static str>,
    pub mut_auth_done: Option<bool>,
    pub encap_state: Option<&'static str>,
    // Round 3: Chunking fields
    pub chunk_status: Option<&'static str>,
    pub chunk_seq_num: Option<u32>,
    pub chunk_handle: Option<u8>,
    pub chunk_session_id: Option<u32>,
}

/// Extract modeled capability flags from request capability bitfield.
pub fn req_cap_flags(flags: crate::protocol::SpdmRequestCapabilityFlags) -> alloc::vec::Vec<&'static str> {
    use crate::protocol::SpdmRequestCapabilityFlags;
    let mut v = alloc::vec::Vec::new();
    if flags.contains(SpdmRequestCapabilityFlags::HBEAT_CAP) { v.push("HBEAT_CAP"); }
    if flags.contains(SpdmRequestCapabilityFlags::KEY_UPD_CAP) { v.push("KEY_UPD_CAP"); }
    if flags.contains(SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP) { v.push("HANDSHAKE_IN_THE_CLEAR_CAP"); }
    if flags.contains(SpdmRequestCapabilityFlags::PSK_CAP) { v.push("PSK_CAP"); }
    if flags.contains(SpdmRequestCapabilityFlags::MUT_AUTH_CAP) { v.push("MUT_AUTH_CAP"); }
    if flags.contains(SpdmRequestCapabilityFlags::CHUNK_CAP) { v.push("CHUNK_CAP"); }
    v
}

/// Extract modeled capability flags from response capability bitfield.
pub fn rsp_cap_flags(flags: crate::protocol::SpdmResponseCapabilityFlags) -> alloc::vec::Vec<&'static str> {
    use crate::protocol::SpdmResponseCapabilityFlags;
    let mut v = alloc::vec::Vec::new();
    if flags.contains(SpdmResponseCapabilityFlags::HBEAT_CAP) { v.push("HBEAT_CAP"); }
    if flags.contains(SpdmResponseCapabilityFlags::KEY_UPD_CAP) { v.push("KEY_UPD_CAP"); }
    if flags.contains(SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP) { v.push("HANDSHAKE_IN_THE_CLEAR_CAP"); }
    if flags.contains(SpdmResponseCapabilityFlags::PSK_CAP_WITH_CONTEXT) { v.push("PSK_CAP"); }
    if flags.contains(SpdmResponseCapabilityFlags::PSK_CAP_WITHOUT_CONTEXT) { v.push("PSK_CAP"); }
    if flags.contains(SpdmResponseCapabilityFlags::MUT_AUTH_CAP) { v.push("MUT_AUTH_CAP"); }
    if flags.contains(SpdmResponseCapabilityFlags::CHUNK_CAP) { v.push("CHUNK_CAP"); }
    v
}

/// Extract PSK capability mode from response flags.
pub fn rsp_psk_cap_mode(flags: crate::protocol::SpdmResponseCapabilityFlags) -> Option<&'static str> {
    use crate::protocol::SpdmResponseCapabilityFlags;
    if flags.contains(SpdmResponseCapabilityFlags::PSK_CAP_WITH_CONTEXT) {
        Some("WithContext")
    } else if flags.contains(SpdmResponseCapabilityFlags::PSK_CAP_WITHOUT_CONTEXT) {
        Some("WithoutContext")
    } else {
        None
    }
}

/// Map base_hash_sel to abstract algorithm name for trace.
pub fn algo_name(hash: crate::protocol::SpdmBaseHashAlgo) -> &'static str {
    use crate::protocol::SpdmBaseHashAlgo;
    if hash == SpdmBaseHashAlgo::TPM_ALG_SHA_384 { "a1" }
    else if hash == SpdmBaseHashAlgo::TPM_ALG_SHA_256 { "a2" }
    else if hash == SpdmBaseHashAlgo::TPM_ALG_SHA_512 { "a1" }
    else { "a1" }
}

/// Map session state enum to string for trace.
pub fn session_state_str(state: SpdmSessionState) -> &'static str {
    match state {
        SpdmSessionState::SpdmSessionNotStarted => "NotStarted",
        SpdmSessionState::SpdmSessionHandshaking => "Handshaking",
        SpdmSessionState::SpdmSessionEstablished => "Established",
        _ => "NotStarted",
    }
}

/// Map connection state enum to string for trace.
pub fn connection_state_str(state: SpdmConnectionState) -> &'static str {
    match state {
        SpdmConnectionState::SpdmConnectionNotStarted => "NotStarted",
        SpdmConnectionState::SpdmConnectionAfterVersion => "AfterVersion",
        SpdmConnectionState::SpdmConnectionAfterCapabilities => "AfterCapabilities",
        SpdmConnectionState::SpdmConnectionNegotiated => "Negotiated",
        SpdmConnectionState::SpdmConnectionAfterCertificate => "AfterCertificate",
        SpdmConnectionState::SpdmConnectionAuthenticated => "Authenticated",
        _ => "NotStarted",
    }
}

/// Map SpdmVersion to u8 version number for trace.
/// Spec uses decimal: SPDM 1.0→10, 1.1→11, 1.2→12, etc.
pub fn version_number(v: crate::protocol::SpdmVersion) -> u8 {
    use crate::protocol::SpdmVersion;
    match v {
        SpdmVersion::SpdmVersion10 => 10,
        SpdmVersion::SpdmVersion11 => 11,
        SpdmVersion::SpdmVersion12 => 12,
        SpdmVersion::SpdmVersion13 => 13,
        SpdmVersion::SpdmVersion14 => 14,
    }
}

/// Emit a Round 2 trace event via the registered callback.
/// This is a lightweight shim: it builds a TraceEvent with the R2 fields
/// stored in the `r2` extension field and fires the callback.
pub fn emit_r2_event(
    role: TraceRole,
    name: &'static str,
    r2: TraceR2Fields,
) {
    let callback = TRACE_RUNTIME.lock().callback;
    if let Some(callback) = callback {
        let event = TraceEvent {
            name,
            nid: role_name(role),
            state: TraceStateSnapshot::default(),
            msg: TraceMessage::default(),
            r2: Some(r2),
        };
        callback(&event);
    }
}
