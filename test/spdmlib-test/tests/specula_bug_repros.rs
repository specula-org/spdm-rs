// Copyright (c) 2025
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::{Codec, Reader, Writer};
use spdmlib::common::SpdmCodec;
use spdmlib::common::session::{SpdmSession, SpdmSessionState};
use spdmlib::crypto::SpdmHkdf;
use spdmlib::message::key_update::SpdmKeyUpdateOperation;
use spdmlib::message::{
    SpdmCertificateResponsePayload, SpdmKeyUpdateRequestPayload, SpdmKeyUpdateResponsePayload,
    SpdmMessage, SpdmMessageHeader, SpdmMessagePayload, SpdmRequestResponseCode,
    MAX_SPDM_CERT_PORTION_LEN,
};
use spdmlib::protocol::{
    gen_array_clone, SpdmAeadAlgo, SpdmBaseHashAlgo, SpdmCertChainBuffer, SpdmDigestStruct,
    SpdmDheAlgo, SpdmHkdfInputKeyingMaterial, SpdmHkdfOutputKeyingMaterial,
    SpdmHkdfPseudoRandomKey, SpdmKemAlgo, SpdmKeyScheduleAlgo, SpdmSharedSecretFinalKeyStruct,
    SpdmVersion, SPDM_MAX_HASH_SIZE, SPDM_MAX_HKDF_OKM_SIZE, SPDM_MAX_SHARED_SECRET_SIZE,
};
use spdmlib::responder::ResponderContext;
use spdmlib::secret;
use spdmlib_test::common::device_io::{FakeSpdmDeviceIoReceve, SharedBuffer};
use spdmlib_test::common::secret_callback::{
    SECRET_ASYM_IMPL_INSTANCE, SECRET_PQC_ASYM_IMPL_INSTANCE,
};
use spdmlib_test::common::transport::PciDoeTransportEncap;
use spdmlib_test::common::util::{create_info, get_test_key_directory, TestCase};
use spin::Mutex;
use std::fs;
use std::sync::Arc;

const TRAFFIC_UPDATE_LABEL: &[u8] = b"traffic upd";

fn hkdf_extract_passthrough(
    hash_algo: SpdmBaseHashAlgo,
    _salt: &[u8],
    _ikm: &SpdmHkdfInputKeyingMaterial,
) -> Option<SpdmHkdfPseudoRandomKey> {
    let data_size = match hash_algo {
        SpdmBaseHashAlgo::TPM_ALG_SHA_256 => 32,
        SpdmBaseHashAlgo::TPM_ALG_SHA_384 => 48,
        SpdmBaseHashAlgo::TPM_ALG_SHA_512 => 64,
        _ => return None,
    };
    Some(SpdmHkdfPseudoRandomKey {
        data_size,
        data: Box::new([0x5Au8; SPDM_MAX_HASH_SIZE]),
    })
}

fn hkdf_expand_fail_on_update(
    hash_algo: SpdmBaseHashAlgo,
    _prk: &SpdmHkdfPseudoRandomKey,
    info: &[u8],
    out_size: u16,
) -> Option<SpdmHkdfOutputKeyingMaterial> {
    if info.windows(TRAFFIC_UPDATE_LABEL.len())
        .any(|window| window == TRAFFIC_UPDATE_LABEL)
    {
        return None;
    }

    if out_size as usize > SPDM_MAX_HKDF_OKM_SIZE {
        return None;
    }

    let data_size = match hash_algo {
        SpdmBaseHashAlgo::TPM_ALG_SHA_256
        | SpdmBaseHashAlgo::TPM_ALG_SHA_384
        | SpdmBaseHashAlgo::TPM_ALG_SHA_512 => out_size,
        _ => return None,
    };

    Some(SpdmHkdfOutputKeyingMaterial {
        data_size,
        data: Box::new([0xA5u8; SPDM_MAX_HKDF_OKM_SIZE]),
    })
}

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

fn setup_responder_key_update_context() -> (ResponderContext, u32) {
    let (rsp_config_info, rsp_provision_info) = create_info();
    let shared_buffer = SharedBuffer::new();
    let device_io_responder = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
        shared_buffer,
    ))));
    let transport_encap_responder = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let mut responder = ResponderContext::new(
        device_io_responder,
        transport_encap_responder,
        rsp_config_info,
        rsp_provision_info,
    );

    let rsp_session_id = 0xFFFEu16;
    let session_id = (0xffu32 << 16) + rsp_session_id as u32;
    responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    responder.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
    responder.common.session = gen_array_clone(SpdmSession::new(), 4);
    setup_established_session(&mut responder.common.session[0], session_id);
    (responder, session_id)
}

fn build_requester_cert_chain_buffer() -> SpdmCertChainBuffer {
    let key_dir = get_test_key_directory();
    let ca = fs::read(key_dir.join("test_key/ecp384/ca.cert.der")).expect("read ca cert");
    let inter = fs::read(key_dir.join("test_key/ecp384/inter.cert.der")).expect("read inter cert");
    let leaf = fs::read(key_dir.join("test_key/ecp384/end_requester_with_spdm_req_eku.cert.der"))
        .expect("read requester leaf cert");

    let mut chain = Vec::with_capacity(ca.len() + inter.len() + leaf.len());
    chain.extend_from_slice(&ca);
    chain.extend_from_slice(&inter);
    chain.extend_from_slice(&leaf);

    TestCase::get_certificate_chain_buffer(SpdmBaseHashAlgo::TPM_ALG_SHA_384, &chain)
}

fn send_cert_chain_to_responder(
    responder: &mut ResponderContext,
    chain: &SpdmCertChainBuffer,
) -> spdmlib::error::SpdmResult<bool> {
    let mut offset = 0usize;
    loop {
        let portion_len = (chain.data_size as usize - offset).min(MAX_SPDM_CERT_PORTION_LEN);
        let remainder_len = chain.data_size as usize - offset - portion_len;
        let mut cert_portion = [0u8; MAX_SPDM_CERT_PORTION_LEN];
        cert_portion[..portion_len]
            .copy_from_slice(&chain.data[offset..offset + portion_len]);

        let message = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion12,
                request_response_code: SpdmRequestResponseCode::SpdmResponseCertificate,
            },
            payload: SpdmMessagePayload::SpdmCertificateResponse(SpdmCertificateResponsePayload {
                slot_id: 0,
                portion_length: portion_len as u32,
                remainder_length: remainder_len as u32,
                cert_chain: cert_portion,
            }),
        };

        let mut raw = [0u8; 2048];
        let mut writer = Writer::init(&mut raw);
        message
            .spdm_encode(&mut responder.common, &mut writer)
            .expect("encode certificate response");

        let result = responder.handle_encap_response_certificate(writer.used_slice());
        if result.is_err() || remainder_len == 0 {
            return result;
        }

        offset += portion_len;
    }
}

#[test]
fn repro_key_update_ack_without_applied_update() {
    secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    secret::pqc_asym_sign::register(SECRET_PQC_ASYM_IMPL_INSTANCE.clone());
    assert!(spdmlib::crypto::hkdf::register(SpdmHkdf {
        hkdf_extract_cb: hkdf_extract_passthrough,
        hkdf_expand_cb: hkdf_expand_fail_on_update,
    }));

    let (mut responder, session_id) = setup_responder_key_update_context();
    let old_secret = responder.common.session[0]
        .get_application_secret()
        .request_data_secret
        .clone();

    let request = SpdmMessage {
        header: SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion12,
            request_response_code: SpdmRequestResponseCode::SpdmRequestKeyUpdate,
        },
        payload: SpdmMessagePayload::SpdmKeyUpdateRequest(SpdmKeyUpdateRequestPayload {
            key_update_operation: SpdmKeyUpdateOperation::SpdmUpdateSingleKey,
            tag: 7,
        }),
    };
    let mut request_bytes = [0u8; 1024];
    let mut request_writer = Writer::init(&mut request_bytes);
    request
        .spdm_encode(&mut responder.common, &mut request_writer)
        .expect("encode key update request");

    let mut response_bytes = [0u8; 1024];
    let mut response_writer = Writer::init(&mut response_bytes);
    let (status, response) =
        responder.handle_spdm_key_update(session_id, request_writer.used_slice(), &mut response_writer);

    assert!(status.is_ok(), "responder should still return success");
    let response = response.expect("response buffer");

    let mut reader = Reader::init(response);
    let header = SpdmMessageHeader::read(&mut reader).expect("response header");
    assert_eq!(
        header.request_response_code,
        SpdmRequestResponseCode::SpdmResponseKeyUpdateAck
    );
    let ack = SpdmKeyUpdateResponsePayload::spdm_read(&mut responder.common, &mut reader)
        .expect("key update ack payload");
    assert_eq!(ack.key_update_operation, SpdmKeyUpdateOperation::SpdmUpdateSingleKey);

    let new_secret = responder.common.session[0]
        .get_application_secret()
        .request_data_secret
        .clone();
    assert_eq!(
        old_secret, new_secret,
        "the responder ACKed the update even though its request-direction key did not change"
    );
}

#[test]
fn repro_mut_auth_rejects_valid_requester_eku_chain() {
    secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    secret::pqc_asym_sign::register(SECRET_PQC_ASYM_IMPL_INSTANCE.clone());

    let (config_info, provision_info) = create_info();
    let transport = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let shared_buffer = SharedBuffer::new();
    let device_io = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
        shared_buffer,
    ))));
    let mut responder = ResponderContext::new(device_io, transport, config_info, provision_info);
    responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    responder.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
    responder.common.encap_context.req_slot_id = 0;
    responder.common.peer_info.peer_cert_chain_temp = Some(SpdmCertChainBuffer::default());

    let requester_chain = build_requester_cert_chain_buffer();
    let result = send_cert_chain_to_responder(&mut responder, &requester_chain);

    assert!(
        result.is_err(),
        "the responder currently rejects a requester-auth-only certificate chain in mutual auth"
    );
}
