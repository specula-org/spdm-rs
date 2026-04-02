// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::{
    error::{SpdmResult, SPDM_STATUS_INVALID_MSG_FIELD, SPDM_STATUS_INVALID_STATE_LOCAL},
    message::SpdmKeyExchangeMutAuthAttributes,
    spdm_trace::{self, TraceRole, TraceR2Fields},
};

use super::RequesterContext;

impl RequesterContext {
    #[maybe_async::maybe_async]
    pub async fn session_based_mutual_authenticate(&mut self, session_id: u32) -> SpdmResult<()> {
        self.common.construct_my_cert_chain()?;

        let spdm_session = self
            .common
            .get_session_via_id(session_id)
            .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?;

        let mut_auth_requested = spdm_session.get_mut_auth_requested();

        // R3: SelectMutAuthMode
        let mode_str = match mut_auth_requested {
            SpdmKeyExchangeMutAuthAttributes::MUT_AUTH_REQ => "MutAuthReq",
            SpdmKeyExchangeMutAuthAttributes::MUT_AUTH_REQ_WITH_ENCAP_REQUEST => "WithEncap",
            SpdmKeyExchangeMutAuthAttributes::MUT_AUTH_REQ_WITH_GET_DIGESTS => "WithGetDigests",
            _ => "None",
        };
        spdm_trace::emit_r2_event(
            TraceRole::Requester,
            "SelectMutAuthMode",
            TraceR2Fields {
                session_id: Some(session_id),
                mut_auth_mode: Some(mode_str),
                ..Default::default()
            },
        );

        match mut_auth_requested {
            SpdmKeyExchangeMutAuthAttributes::MUT_AUTH_REQ => Ok(()),
            SpdmKeyExchangeMutAuthAttributes::MUT_AUTH_REQ_WITH_ENCAP_REQUEST
            | SpdmKeyExchangeMutAuthAttributes::MUT_AUTH_REQ_WITH_GET_DIGESTS => {
                self.get_encapsulated_request_response(session_id, mut_auth_requested)
                    .await
            }
            _ => Err(SPDM_STATUS_INVALID_MSG_FIELD),
        }
    }
}
