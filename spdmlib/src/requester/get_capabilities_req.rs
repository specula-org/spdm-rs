// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::error::{SpdmResult, SPDM_STATUS_ERROR_PEER, SPDM_STATUS_INVALID_MSG_FIELD};
use crate::message::*;
use crate::protocol::*;
use crate::requester::*;
use crate::spdm_trace::{self, TraceRole, TraceR2Fields};

impl RequesterContext {
    #[maybe_async::maybe_async]
    pub async fn send_spdm_capability(&mut self, send_buffer: &mut [u8]) -> SpdmResult<usize> {
        info!("!!! send capability !!!");
        self.common.reset_buffer_via_request_code(
            SpdmRequestResponseCode::SpdmRequestGetCapabilities,
            None,
        );

        let send_used = self.encode_spdm_capability(send_buffer)?;
        spdm_trace::emit_r2_event(
            TraceRole::Requester,
            "RequesterSendGetCapabilities",
            TraceR2Fields {
                req_caps: Some(spdm_trace::req_cap_flags(self.common.config_info.req_capabilities)),
                ..Default::default()
            },
        );
        self.send_message(None, &send_buffer[..send_used], false)
            .await?;
        Ok(send_used)
    }

    #[maybe_async::maybe_async]
    pub async fn receive_spdm_capability(&mut self, send_buffer: &[u8]) -> SpdmResult {
        info!("!!! receive capability !!!");
        let mut receive_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let used = self
            .receive_message(None, &mut receive_buffer, false)
            .await?;
        self.handle_spdm_capability_response(0, send_buffer, &receive_buffer[..used])
    }

    #[maybe_async::maybe_async]
    pub async fn send_receive_spdm_capability(&mut self) -> SpdmResult {
        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let send_used = self.send_spdm_capability(&mut send_buffer).await?;
        self.receive_spdm_capability(&send_buffer[..send_used])
            .await
    }

    pub fn encode_spdm_capability(&mut self, buf: &mut [u8]) -> SpdmResult<usize> {
        let mut writer = Writer::init(buf);
        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmRequestGetCapabilities,
            },
            payload: SpdmMessagePayload::SpdmGetCapabilitiesRequest(
                SpdmGetCapabilitiesRequestPayload {
                    ct_exponent: self.common.config_info.req_ct_exponent,
                    flags: self.common.config_info.req_capabilities,
                    data_transfer_size: self.common.config_info.data_transfer_size,
                    max_spdm_msg_size: self.common.config_info.max_spdm_msg_size,
                    ex_flags: SpdmRequestCapabilityExFlags::default(),
                },
            ),
        };
        request.spdm_encode(&mut self.common, &mut writer)
    }

    pub fn handle_spdm_capability_response(
        &mut self,
        session_id: u32,
        send_buffer: &[u8],
        receive_buffer: &[u8],
    ) -> SpdmResult {
        let mut reader = Reader::init(receive_buffer);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => {
                if message_header.version != self.common.negotiate_info.spdm_version_sel {
                    return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                }
                match message_header.request_response_code {
                    SpdmRequestResponseCode::SpdmResponseCapabilities => {
                        let capabilities = SpdmCapabilitiesResponsePayload::spdm_read(
                            &mut self.common,
                            &mut reader,
                        );
                        let used = reader.used();
                        if let Some(capabilities) = capabilities {
                            debug!("!!! capabilities : {:02x?}\n", capabilities);
                            self.common.negotiate_info.req_ct_exponent_sel =
                                self.common.config_info.req_ct_exponent;
                            self.common.negotiate_info.req_capabilities_sel =
                                self.common.config_info.req_capabilities;
                            self.common.negotiate_info.rsp_ct_exponent_sel =
                                capabilities.ct_exponent;
                            self.common.negotiate_info.rsp_capabilities_sel = capabilities.flags;

                            if self.common.negotiate_info.spdm_version_sel
                                >= SpdmVersion::SpdmVersion12
                            {
                                self.common.negotiate_info.req_data_transfer_size_sel =
                                    self.common.config_info.data_transfer_size;
                                self.common.negotiate_info.req_max_spdm_msg_size_sel =
                                    self.common.config_info.max_spdm_msg_size;
                                self.common.negotiate_info.rsp_data_transfer_size_sel =
                                    capabilities.data_transfer_size;
                                self.common.negotiate_info.rsp_max_spdm_msg_size_sel =
                                    capabilities.max_spdm_msg_size;
                            }

                            self.common.append_message_a(send_buffer)?;
                            self.common.append_message_a(&receive_buffer[..used])?;

                            spdm_trace::emit_r2_event(
                                TraceRole::Requester,
                                "HandleSpdmCapabilitiesResponse",
                                TraceR2Fields {
                                    req_connection_state: Some(crate::common::SpdmConnectionState::SpdmConnectionAfterCapabilities),
                                    req_capabilities: Some(spdm_trace::req_cap_flags(self.common.negotiate_info.req_capabilities_sel)),
                                    rsp_capabilities: Some(spdm_trace::rsp_cap_flags(self.common.negotiate_info.rsp_capabilities_sel)),
                                    ..Default::default()
                                },
                            );

                            Ok(())
                        } else {
                            error!("!!! capabilities : fail !!!\n");
                            Err(SPDM_STATUS_INVALID_MSG_FIELD)
                        }
                    }
                    SpdmRequestResponseCode::SpdmResponseError => self
                        .spdm_handle_error_response_main(
                            Some(session_id),
                            receive_buffer,
                            SpdmRequestResponseCode::SpdmRequestGetCapabilities,
                            SpdmRequestResponseCode::SpdmResponseCapabilities,
                        ),
                    _ => Err(SPDM_STATUS_ERROR_PEER),
                }
            }
            None => Err(SPDM_STATUS_INVALID_MSG_FIELD),
        }
    }
}
