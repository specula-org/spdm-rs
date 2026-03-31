// Copyright (c) 2025
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::session::{SpdmSession, SpdmSessionState};
use crate::common::{SpdmConnectionState, SpdmContext};
use spin::Mutex;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceKeyState {
    Old,
    New,
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
    pub req_key_state: Option<TraceKeyState>,
    pub rsp_key_state: Option<TraceKeyState>,
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
}

#[derive(Clone, Copy, Debug)]
pub struct TraceEvent {
    pub name: &'static str,
    pub nid: &'static str,
    pub state: TraceStateSnapshot,
    pub msg: TraceMessage,
}

#[derive(Clone, Copy, Debug)]
struct TraceRuntime {
    callback: Option<fn(&TraceEvent)>,
    requester_connection: SpdmConnectionState,
    requester_transcript: TraceTranscriptPhase,
    responder_transcript: TraceTranscriptPhase,
    req_key_state: TraceKeyState,
    rsp_key_state: TraceKeyState,
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
            req_key_state: TraceKeyState::Old,
            rsp_key_state: TraceKeyState::Old,
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
    req_key_state: TraceKeyState::Old,
    rsp_key_state: TraceKeyState::Old,
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

pub fn note_key_update_response(op: TraceKeyUpdateOp) {
    let mut runtime = TRACE_RUNTIME.lock();
    match op {
        TraceKeyUpdateOp::UpdateSingle => runtime.req_key_state = TraceKeyState::New,
        TraceKeyUpdateOp::UpdateAll => {
            runtime.req_key_state = TraceKeyState::New;
            runtime.rsp_key_state = TraceKeyState::New;
        }
        TraceKeyUpdateOp::VerifyNewKey => {}
    }
}

pub fn note_key_update_ack(op: TraceKeyUpdateOp) {
    let mut runtime = TRACE_RUNTIME.lock();
    match op {
        TraceKeyUpdateOp::UpdateSingle => runtime.req_key_state = TraceKeyState::New,
        TraceKeyUpdateOp::UpdateAll => {
            runtime.req_key_state = TraceKeyState::New;
            runtime.rsp_key_state = TraceKeyState::New;
        }
        TraceKeyUpdateOp::VerifyNewKey => {}
    }
}

pub fn note_key_update_rollback(req_backup_valid: bool, rsp_backup_valid: bool) {
    let mut runtime = TRACE_RUNTIME.lock();
    if req_backup_valid {
        runtime.req_key_state = TraceKeyState::Old;
    }
    if rsp_backup_valid {
        runtime.rsp_key_state = TraceKeyState::Old;
    }
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

    let (callback, remote, req_key_state, rsp_key_state) = {
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
            runtime.req_key_state,
            runtime.rsp_key_state,
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
            state.req_key_state = Some(req_key_state);
            state.rsp_key_state = Some(rsp_key_state);
            state.req_backup_valid = Some(req_backup_valid);
            state.rsp_backup_valid = Some(rsp_backup_valid);
        }

        let event = TraceEvent {
            name,
            nid: role_name(role),
            state,
            msg,
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
