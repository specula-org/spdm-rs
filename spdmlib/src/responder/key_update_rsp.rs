// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::SpdmCodec;
use crate::error::SpdmResult;
use crate::error::SPDM_STATUS_INVALID_MSG_FIELD;
use crate::error::SPDM_STATUS_INVALID_STATE_LOCAL;
use crate::message::*;
use crate::responder::*;
use crate::spdm_trace::{self, TraceKeyUpdateOp, TraceMessage, TraceRole, TraceR2Fields};

impl ResponderContext {
    pub fn handle_spdm_key_update<'a>(
        &mut self,
        session_id: u32,
        bytes: &[u8],
        writer: &'a mut Writer,
    ) -> (SpdmResult, Option<&'a [u8]>) {
        self.write_spdm_key_update_response(session_id, bytes, writer)
    }

    pub fn write_spdm_key_update_response<'a>(
        &mut self,
        session_id: u32,
        bytes: &[u8],
        writer: &'a mut Writer,
    ) -> (SpdmResult, Option<&'a [u8]>) {
        let mut reader = Reader::init(bytes);
        let message_header = SpdmMessageHeader::read(&mut reader);
        if let Some(message_header) = message_header {
            if message_header.version != self.common.negotiate_info.spdm_version_sel {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorVersionMismatch, 0, writer);
                return (
                    Err(SPDM_STATUS_INVALID_MSG_FIELD),
                    Some(writer.used_slice()),
                );
            }
        } else {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_MSG_FIELD),
                Some(writer.used_slice()),
            );
        }

        self.common.reset_buffer_via_request_code(
            SpdmRequestResponseCode::SpdmRequestKeyUpdate,
            Some(session_id),
        );

        let key_update_req = SpdmKeyUpdateRequestPayload::spdm_read(&mut self.common, &mut reader);
        if let Some(key_update_req) = &key_update_req {
            debug!("!!! key_update req : {:02x?}\n", key_update_req);
        } else {
            error!("!!! key_update req : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_MSG_FIELD),
                Some(writer.used_slice()),
            );
        }
        let key_update_req = key_update_req.unwrap();

        let spdm_version_sel = self.common.negotiate_info.spdm_version_sel;
        let session = if let Some(session) = self.common.get_session_via_id(session_id) {
            session
        } else {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_STATE_LOCAL),
                Some(writer.used_slice()),
            );
        };
        match key_update_req.key_update_operation {
            SpdmKeyUpdateOperation::SpdmUpdateSingleKey => {
                let create_res = session.create_data_secret_update(spdm_version_sel, true, false);
                let req_ok = create_res.is_ok();
                let _ = create_res;
                spdm_trace::note_key_update_response(TraceKeyUpdateOp::UpdateSingle, req_ok, true);
            }
            SpdmKeyUpdateOperation::SpdmUpdateAllKeys => {
                let create_res = session.create_data_secret_update(spdm_version_sel, true, true);
                let req_ok = create_res.is_ok();
                let _ = create_res;
                let activate_res = session.activate_data_secret_update(spdm_version_sel, false, true, true);
                let resp_ok = activate_res.is_ok();
                let _ = activate_res;
                spdm_trace::note_key_update_response(TraceKeyUpdateOp::UpdateAll, req_ok, resp_ok);
            }
            SpdmKeyUpdateOperation::SpdmVerifyNewKey => {
                let _ = session.activate_data_secret_update(spdm_version_sel, true, false, true);
                spdm_trace::note_key_update_response(TraceKeyUpdateOp::VerifyNewKey, true, true);
            }
            _ => {
                error!("!!! key_update req : fail !!!\n");
                self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
                return (
                    Err(SPDM_STATUS_INVALID_MSG_FIELD),
                    Some(writer.used_slice()),
                );
            }
        }

        info!("send spdm key_update rsp\n");

        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmResponseKeyUpdateAck,
            },
            payload: SpdmMessagePayload::SpdmKeyUpdateResponse(SpdmKeyUpdateResponsePayload {
                key_update_operation: key_update_req.key_update_operation,
                tag: key_update_req.tag,
            }),
        };
        let res = response.spdm_encode(&mut self.common, writer);
        if res.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_STATE_LOCAL),
                Some(writer.used_slice()),
            );
        }

        let op = match key_update_req.key_update_operation {
            SpdmKeyUpdateOperation::SpdmUpdateSingleKey => TraceKeyUpdateOp::UpdateSingle,
            SpdmKeyUpdateOperation::SpdmUpdateAllKeys => TraceKeyUpdateOp::UpdateAll,
            SpdmKeyUpdateOperation::SpdmVerifyNewKey => TraceKeyUpdateOp::VerifyNewKey,
            _ => unreachable!(),
        };
        spdm_trace::emit_key_event(
            TraceRole::Responder,
            &self.common,
            session_id,
            "ResponderHandleKeyUpdate",
            TraceMessage {
                op: Some(op),
                ..TraceMessage::default()
            },
        );

        // R2: emit with session backup state
        {
            let (rbv, sbv) = self.common.get_immutable_session_via_id(session_id)
                .map(|s| (s.get_requester_backup_valid(), s.get_responder_backup_valid()))
                .unwrap_or((false, false));
            spdm_trace::emit_r2_event(
                TraceRole::Responder,
                "WriteSpdmKeyUpdateResponse",
                TraceR2Fields {
                    session_id: Some(session_id),
                    req_backup_valid: Some(rbv),
                    rsp_backup_valid: Some(sbv),
                    ..Default::default()
                },
            );
        }

        (Ok(()), Some(writer.used_slice()))
    }
}
