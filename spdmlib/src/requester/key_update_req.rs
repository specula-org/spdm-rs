// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::error::{
    SpdmResult, SPDM_STATUS_ERROR_PEER, SPDM_STATUS_INVALID_MSG_FIELD,
    SPDM_STATUS_INVALID_PARAMETER,
};
use crate::message::*;
use crate::requester::*;
use crate::spdm_trace::{
    self, TraceErrorKind, TraceKeyUpdateOp, TraceMessage, TraceRole, TraceR2Fields,
};

impl RequesterContext {
    #[maybe_async::maybe_async]
    pub async fn send_spdm_key_update(
        &mut self,
        session_id: u32,
        key_update_operation: SpdmKeyUpdateOperation,
        tag: u8,
    ) -> SpdmResult {
        info!("send spdm key_update\n");

        self.common.reset_buffer_via_request_code(
            SpdmRequestResponseCode::SpdmRequestKeyUpdate,
            Some(session_id),
        );

        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let used = self.encode_spdm_key_update_op(key_update_operation, tag, &mut send_buffer)?;
        self.send_message(Some(session_id), &send_buffer[..used], false)
            .await?;

        spdm_trace::emit_local_event(
            TraceRole::Requester,
            &self.common,
            Some(session_id),
            "SendKeyUpdate",
            TraceMessage {
                op: Some(match key_update_operation {
                    SpdmKeyUpdateOperation::SpdmUpdateSingleKey => TraceKeyUpdateOp::UpdateSingle,
                    SpdmKeyUpdateOperation::SpdmUpdateAllKeys => TraceKeyUpdateOp::UpdateAll,
                    SpdmKeyUpdateOperation::SpdmVerifyNewKey => TraceKeyUpdateOp::VerifyNewKey,
                    _ => TraceKeyUpdateOp::VerifyNewKey,
                }),
                ..TraceMessage::default()
            },
        );

        // R2: emit key update send
        spdm_trace::emit_r2_event(
            TraceRole::Requester,
            "RequesterSendKeyUpdate",
            TraceR2Fields {
                session_id: Some(session_id),
                op: Some(match key_update_operation {
                    SpdmKeyUpdateOperation::SpdmUpdateSingleKey => "OpUpdateSingle",
                    SpdmKeyUpdateOperation::SpdmUpdateAllKeys => "OpUpdateAll",
                    SpdmKeyUpdateOperation::SpdmVerifyNewKey => "OpVerifyNewKey",
                    _ => "OpVerifyNewKey",
                }),
                ..Default::default()
            },
        );

        Ok(())
    }

    #[maybe_async::maybe_async]
    pub async fn receive_spdm_key_update(
        &mut self,
        session_id: u32,
        key_update_operation: SpdmKeyUpdateOperation,
    ) -> SpdmResult {
        let update_requester = key_update_operation == SpdmKeyUpdateOperation::SpdmUpdateSingleKey
            || key_update_operation == SpdmKeyUpdateOperation::SpdmUpdateAllKeys;
        let update_responder = key_update_operation == SpdmKeyUpdateOperation::SpdmUpdateAllKeys;

        // update key
        let spdm_version_sel = self.common.negotiate_info.spdm_version_sel;
        let session = if let Some(s) = self.common.get_session_via_id(session_id) {
            s
        } else {
            return Err(SPDM_STATUS_INVALID_PARAMETER);
        };
        session.create_data_secret_update(spdm_version_sel, update_requester, update_responder)?;

        let mut receive_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let used = self
            .receive_message(Some(session_id), &mut receive_buffer, false)
            .await?;

        self.handle_spdm_key_update_op_response(
            session_id,
            update_requester,
            update_responder,
            &receive_buffer[..used],
        )
    }

    pub fn encode_spdm_key_update_op(
        &mut self,
        key_update_operation: SpdmKeyUpdateOperation,
        tag: u8,
        buf: &mut [u8],
    ) -> SpdmResult<usize> {
        let mut writer = Writer::init(buf);
        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmRequestKeyUpdate,
            },
            payload: SpdmMessagePayload::SpdmKeyUpdateRequest(SpdmKeyUpdateRequestPayload {
                key_update_operation,
                tag,
            }),
        };
        request.spdm_encode(&mut self.common, &mut writer)
    }

    pub fn handle_spdm_key_update_op_response(
        &mut self,
        session_id: u32,
        update_requester: bool,
        update_responder: bool,
        receive_buffer: &[u8],
    ) -> SpdmResult {
        let mut reader = Reader::init(receive_buffer);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => {
                if message_header.version != self.common.negotiate_info.spdm_version_sel {
                    return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                }
                match message_header.request_response_code {
                    SpdmRequestResponseCode::SpdmResponseKeyUpdateAck => {
                        let key_update_rsp =
                            SpdmKeyUpdateResponsePayload::spdm_read(&mut self.common, &mut reader);
                        let spdm_version_sel = self.common.negotiate_info.spdm_version_sel;
                        let session = if let Some(s) = self.common.get_session_via_id(session_id) {
                            s
                        } else {
                            return Err(SPDM_STATUS_INVALID_PARAMETER);
                        };
                        if let Some(key_update_rsp) = key_update_rsp {
                            debug!("!!! key_update rsp : {:02x?}\n", key_update_rsp);
                            session.activate_data_secret_update(
                                spdm_version_sel,
                                update_requester,
                                update_responder,
                                true,
                            )?;
                            spdm_trace::note_key_update_ack(match key_update_rsp.key_update_operation {
                                SpdmKeyUpdateOperation::SpdmUpdateSingleKey => TraceKeyUpdateOp::UpdateSingle,
                                SpdmKeyUpdateOperation::SpdmUpdateAllKeys => TraceKeyUpdateOp::UpdateAll,
                                SpdmKeyUpdateOperation::SpdmVerifyNewKey => TraceKeyUpdateOp::VerifyNewKey,
                                _ => TraceKeyUpdateOp::VerifyNewKey,
                            });
                            spdm_trace::emit_key_event(
                                TraceRole::Requester,
                                &self.common,
                                session_id,
                                "RequesterHandleKeyUpdateAck",
                                TraceMessage {
                                    op: Some(match key_update_rsp.key_update_operation {
                                        SpdmKeyUpdateOperation::SpdmUpdateSingleKey => TraceKeyUpdateOp::UpdateSingle,
                                        SpdmKeyUpdateOperation::SpdmUpdateAllKeys => TraceKeyUpdateOp::UpdateAll,
                                        SpdmKeyUpdateOperation::SpdmVerifyNewKey => TraceKeyUpdateOp::VerifyNewKey,
                                        _ => TraceKeyUpdateOp::VerifyNewKey,
                                    }),
                                    ..TraceMessage::default()
                                },
                            );
                            // R2: emit with session backup state
                            {
                                let session = self.common.get_immutable_session_via_id(session_id);
                                let (rbv, sbv) = session.map(|s| (s.get_requester_backup_valid(), s.get_responder_backup_valid())).unwrap_or((false, false));
                                spdm_trace::emit_r2_event(
                                    TraceRole::Requester,
                                    "HandleSpdmKeyUpdateResponse",
                                    TraceR2Fields {
                                        session_id: Some(session_id),
                                        req_backup_valid: Some(rbv),
                                        rsp_backup_valid: Some(sbv),
                                        ..Default::default()
                                    },
                                );
                            }
                            Ok(())
                        } else {
                            error!("!!! key_update : fail !!!\n");
                            session.activate_data_secret_update(
                                spdm_version_sel,
                                update_requester,
                                update_responder,
                                false,
                            )?;
                            spdm_trace::note_key_update_rollback(
                                session.get_requester_backup_valid(),
                                session.get_responder_backup_valid(),
                            );
                            spdm_trace::emit_key_event(
                                TraceRole::Requester,
                                &self.common,
                                session_id,
                                "HandleSpdmKeyUpdateOpResponse",
                                TraceMessage {
                                    error: Some(TraceErrorKind::Invalid),
                                    ..TraceMessage::default()
                                },
                            );
                            Err(SPDM_STATUS_INVALID_MSG_FIELD)
                        }
                    }
                    SpdmRequestResponseCode::SpdmResponseError => {
                        let spdm_version_sel = self.common.negotiate_info.spdm_version_sel;
                        let session = if let Some(s) = self.common.get_session_via_id(session_id) {
                            s
                        } else {
                            return Err(SPDM_STATUS_INVALID_PARAMETER);
                        };
                        error!("!!! key_update : fail !!! rollback all keys\n");
                        session.activate_data_secret_update(
                            spdm_version_sel,
                            update_requester,
                            update_responder,
                            false,
                        )?;
                        spdm_trace::note_key_update_rollback(
                            session.get_requester_backup_valid(),
                            session.get_responder_backup_valid(),
                        );
                        spdm_trace::emit_key_event(
                            TraceRole::Requester,
                            &self.common,
                            session_id,
                            "HandleSpdmKeyUpdateOpResponse",
                            TraceMessage {
                                error: Some(TraceErrorKind::Unexpected),
                                ..TraceMessage::default()
                            },
                        );
                        self.spdm_handle_error_response_main(
                            Some(session_id),
                            receive_buffer,
                            SpdmRequestResponseCode::SpdmRequestKeyUpdate,
                            SpdmRequestResponseCode::SpdmResponseKeyUpdateAck,
                        )
                    }
                    _ => Err(SPDM_STATUS_ERROR_PEER),
                }
            }
            None => Err(SPDM_STATUS_INVALID_MSG_FIELD),
        }
    }

    #[maybe_async::maybe_async]
    pub async fn send_receive_spdm_key_update(
        &mut self,
        session_id: u32,
        key_update_operation: SpdmKeyUpdateOperation,
    ) -> SpdmResult {
        if key_update_operation != SpdmKeyUpdateOperation::SpdmUpdateAllKeys
            && key_update_operation != SpdmKeyUpdateOperation::SpdmUpdateSingleKey
        {
            return Err(SPDM_STATUS_INVALID_MSG_FIELD);
        }
        self.send_spdm_key_update(session_id, key_update_operation, 1)
            .await?;
        self.receive_spdm_key_update(session_id, key_update_operation)
            .await?;
        self.send_spdm_key_update(session_id, SpdmKeyUpdateOperation::SpdmVerifyNewKey, 2)
            .await?;
        self.receive_spdm_key_update(session_id, SpdmKeyUpdateOperation::SpdmVerifyNewKey)
            .await
    }
}
