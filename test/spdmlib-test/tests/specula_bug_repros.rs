// Copyright (c) 2025
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::{Codec, Reader, Writer};
use spdmlib::common::SpdmCodec;
use spdmlib::common::session::{SpdmSession, SpdmSessionState};
use spdmlib::crypto::SpdmHkdf;
use spdmlib::crypto;
use spdmlib::message::key_update::SpdmKeyUpdateOperation;
use spdmlib::message::{
    SpdmCertificateResponsePayload, SpdmKeyUpdateRequestPayload, SpdmKeyUpdateResponsePayload,
    SpdmFinishRequestPayload,
    SpdmMessage, SpdmMessageHeader, SpdmMessagePayload, SpdmRequestResponseCode,
    MAX_SPDM_CERT_PORTION_LEN,
};
use spdmlib::common::opaque::{SpdmOpaqueStruct, MAX_SPDM_OPAQUE_SIZE};
use spdmlib::protocol::{
    gen_array_clone, SpdmAeadAlgo, SpdmBaseAsymAlgo, SpdmBaseHashAlgo, SpdmCertChainBuffer,
    SpdmDigestStruct, SpdmDheAlgo, SpdmHkdfInputKeyingMaterial, SpdmHkdfOutputKeyingMaterial,
    SpdmHkdfPseudoRandomKey, SpdmKemAlgo, SpdmKeyScheduleAlgo, SpdmSharedSecretFinalKeyStruct,
    SpdmMeasurementSummaryHashType, SpdmSignatureStruct, SpdmVersion, SPDM_MAX_ASYM_SIG_SIZE,
    SPDM_MAX_HASH_SIZE, SPDM_MAX_HKDF_OKM_SIZE, SPDM_MAX_SHARED_SECRET_SIZE,
};
use spdmlib::message::SpdmFinishRequestAttributes;
use spdmlib::requester::RequesterContext;
use spdmlib::responder::ResponderContext;
use spdmlib::secret;
use spdmlib::protocol::{
    SpdmRequestCapabilityFlags, SpdmResponseCapabilityFlags,
};
use spdmlib::watchdog::SpdmWatchDog;
use spdmlib_test::common::crypto_callback::FAKE_HMAC;
use spdmlib_test::common::device_io::{FakeSpdmDeviceIoReceve, SharedBuffer};
use spdmlib_test::common::secret_callback::{
    SECRET_ASYM_IMPL_INSTANCE, SECRET_MEASUREMENT_IMPL_INSTANCE, SECRET_PQC_ASYM_IMPL_INSTANCE,
    SECRET_PSK_IMPL_INSTANCE,
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

fn setup_handshaking_session(session: &mut SpdmSession, session_id: u32, mut_auth: bool) {
    session.setup(session_id).expect("setup session");
    session.set_crypto_param(
        SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        SpdmDheAlgo::SECP_384_R1,
        SpdmKemAlgo::empty(),
        SpdmAeadAlgo::AES_256_GCM,
        SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
    );
    session.set_session_state(SpdmSessionState::SpdmSessionHandshaking);
    if mut_auth {
        session.set_mut_auth_requested(
            spdmlib::message::SpdmKeyExchangeMutAuthAttributes::MUT_AUTH_REQ,
        );
    }
    session.runtime_info.digest_context_th =
        Some(crypto::hash::hash_ctx_init(SpdmBaseHashAlgo::TPM_ALG_SHA_384).unwrap());
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

fn register_test_secrets() {
    secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    secret::pqc_asym_sign::register(SECRET_PQC_ASYM_IMPL_INSTANCE.clone());
    secret::measurement::register(SECRET_MEASUREMENT_IMPL_INSTANCE.clone());
    secret::psk::register(SECRET_PSK_IMPL_INSTANCE.clone());
}

fn start_watchdog(_session_id: u32, _seconds: u16) {}
fn stop_watchdog(_session_id: u32) {}
fn reset_watchdog(_session_id: u32) {}

fn init_watchdog() {
    spdmlib::watchdog::register(SpdmWatchDog {
        start_watchdog_cb: start_watchdog,
        stop_watchdog_cb: stop_watchdog,
        reset_watchdog_cb: reset_watchdog,
    });
}

fn build_finish_request_bytes() -> [u8; 1024] {
    let mut bytes = [0u8; 1024];
    let (config_info, provision_info) = create_info();
    let mut encode_context = spdmlib::common::SpdmContext::new(
        Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(SharedBuffer::new())))),
        Arc::new(Mutex::new(PciDoeTransportEncap {})),
        config_info,
        provision_info,
    );
    encode_context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
    encode_context.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
    encode_context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;

    let mut header_buf = [0u8; 1024];
    let mut header_writer = Writer::init(&mut header_buf);
    SpdmMessageHeader {
        version: SpdmVersion::SpdmVersion12,
        request_response_code: SpdmRequestResponseCode::SpdmRequestFinish,
    }
    .encode(&mut header_writer)
    .expect("encode finish header");

    let mut payload_buf = [0u8; 1024];
    let mut payload_writer = Writer::init(&mut payload_buf);
    SpdmFinishRequestPayload {
        finish_request_attributes: SpdmFinishRequestAttributes::SIGNATURE_INCLUDED,
        req_slot_id: 0,
        signature: SpdmSignatureStruct {
            data_size: 96,
            data: [0xa5u8; SPDM_MAX_ASYM_SIG_SIZE],
        },
        verify_data: SpdmDigestStruct {
            data_size: 48,
            data: Box::new([0x5au8; SPDM_MAX_HASH_SIZE]),
        },
        opaque: SpdmOpaqueStruct {
            data_size: MAX_SPDM_OPAQUE_SIZE as u16,
            data: [100u8; MAX_SPDM_OPAQUE_SIZE],
        },
    }
    .spdm_encode(
        &mut encode_context,
        &mut payload_writer,
    )
    .expect("encode finish payload");

    bytes[..2].copy_from_slice(&header_buf[..2]);
    bytes[2..].copy_from_slice(&payload_buf[..1022]);
    bytes
}

fn setup_requester_responder_pair(
    req_config_info: spdmlib::common::SpdmConfigInfo,
    req_provision_info: spdmlib::common::SpdmProvisionInfo,
    rsp_config_info: spdmlib::common::SpdmConfigInfo,
    rsp_provision_info: spdmlib::common::SpdmProvisionInfo,
) -> (RequesterContext, Arc<Mutex<ResponderContext>>) {
    init_watchdog();
    register_test_secrets();

    let shared_buffer = SharedBuffer::new();
    let device_io_responder = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
        shared_buffer,
    ))));
    let transport_encap_responder = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let responder = Arc::new(Mutex::new(ResponderContext::new(
        device_io_responder,
        transport_encap_responder,
        rsp_config_info,
        rsp_provision_info,
    )));

    let shared_buffer = SharedBuffer::new();
    let device_io_requester = Arc::new(Mutex::new(spdmlib_test::common::device_io::FakeSpdmDeviceIo::new(
        Arc::new(shared_buffer),
        responder.clone(),
    )));
    let transport_encap_requester = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let requester = RequesterContext::new(
        device_io_requester,
        transport_encap_requester,
        req_config_info,
        req_provision_info,
    );

    (requester, responder)
}

fn setup_mut_auth_finish_responder() -> ResponderContext {
    init_watchdog();
    register_test_secrets();
    secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    secret::pqc_asym_sign::register(SECRET_PQC_ASYM_IMPL_INSTANCE.clone());
    crypto::hmac::register(FAKE_HMAC.clone());

    let (config_info, provision_info) = create_info();
    let shared_buffer = SharedBuffer::new();
    let device_io = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(shared_buffer))));
    let transport = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let mut responder = ResponderContext::new(device_io, transport, config_info, provision_info);
    responder.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
    responder.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
    responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    responder.common.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP;
    responder.common.negotiate_info.rsp_capabilities_sel =
        SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;
    responder.common.session = gen_array_clone(SpdmSession::new(), 4);
    setup_handshaking_session(&mut responder.common.session[0], 0xfffdfffd, true);
    setup_handshaking_session(&mut responder.common.session[1], 0xfffcfffc, true);
    responder.common.encap_context.req_slot_id = 0;
    responder
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

#[test]
fn repro_get_version_resets_live_session() {
    let future = async {
        let (req_config_info, req_provision_info) = create_info();
        let (rsp_config_info, rsp_provision_info) = create_info();
        let (mut requester, responder) = setup_requester_responder_pair(
            req_config_info,
            req_provision_info,
            rsp_config_info,
            rsp_provision_info,
        );

        let session_id = 0xfffdfffd;
        requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        setup_established_session(&mut requester.common.session[0], session_id);
        {
            let mut responder = responder.lock();
            responder.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
            setup_established_session(&mut responder.common.session[0], session_id);
        }
        assert!(
            requester.common.get_immutable_session_via_id(session_id).is_some(),
            "requester should have a live session before the reset trigger"
        );
        assert!(
            responder
                .lock()
                .common
                .get_immutable_session_via_id(session_id)
                .is_some(),
            "responder should have a live session before the reset trigger"
        );

        let mut send_buffer = [0u8; spdmlib::config::MAX_SPDM_MSG_SIZE];
        let send_used = requester
            .send_spdm_version(&mut send_buffer)
            .await
            .expect("GET_VERSION send should succeed");

        assert!(
            requester.common.get_immutable_session_via_id(session_id).is_none(),
            "fresh GET_VERSION destroyed the requester's previously established session"
        );
        assert!(
            responder
                .lock()
                .common
                .get_immutable_session_via_id(session_id)
                .is_none(),
            "fresh GET_VERSION destroyed the responder's previously established session"
        );
        assert!(
            requester
                .receive_spdm_version(&send_buffer[..send_used])
                .await
                .is_ok(),
            "the reset is triggered by an otherwise valid GET_VERSION exchange"
        );
    };

    executor::block_on(future);
}

#[test]
fn repro_key_update_without_key_update_capability() {
    let (mut responder, session_id) = setup_responder_key_update_context();
    responder.common.negotiate_info.req_capabilities_sel =
        SpdmRequestCapabilityFlags::empty();
    responder.common.negotiate_info.rsp_capabilities_sel =
        SpdmResponseCapabilityFlags::empty();

    let request = SpdmMessage {
        header: SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion12,
            request_response_code: SpdmRequestResponseCode::SpdmRequestKeyUpdate,
        },
        payload: SpdmMessagePayload::SpdmKeyUpdateRequest(SpdmKeyUpdateRequestPayload {
            key_update_operation: SpdmKeyUpdateOperation::SpdmUpdateSingleKey,
            tag: 1,
        }),
    };
    let mut request_bytes = [0u8; 1024];
    let mut request_writer = Writer::init(&mut request_bytes);
    request
        .spdm_encode(&mut responder.common, &mut request_writer)
        .expect("encode key update request");

    let mut response_bytes = [0u8; 1024];
    let mut response_writer = Writer::init(&mut response_bytes);
    let (status, response) = responder.handle_spdm_key_update(
        session_id,
        request_writer.used_slice(),
        &mut response_writer,
    );

    assert!(
        !responder
            .common
            .negotiate_info
            .req_capabilities_sel
            .contains(SpdmRequestCapabilityFlags::KEY_UPD_CAP)
    );
    assert!(
        !responder
            .common
            .negotiate_info
            .rsp_capabilities_sel
            .contains(SpdmResponseCapabilityFlags::KEY_UPD_CAP)
    );
    assert!(
        status.is_ok(),
        "responder still accepts KEY_UPDATE even though KEY_UPD_CAP was never negotiated"
    );

    let response = response.expect("response buffer");
    let mut reader = Reader::init(response);
    let header = SpdmMessageHeader::read(&mut reader).expect("response header");
    assert_eq!(
        header.request_response_code,
        SpdmRequestResponseCode::SpdmResponseKeyUpdateAck,
        "responder ACKed KEY_UPDATE without negotiated KEY_UPD_CAP"
    );
}

#[test]
fn repro_psk_session_without_psk_capability() {
    let future = async {
        let (mut req_config_info, req_provision_info) = create_info();
        let (mut rsp_config_info, rsp_provision_info) = create_info();
        req_config_info.req_capabilities.remove(SpdmRequestCapabilityFlags::PSK_CAP);
        rsp_config_info
            .rsp_capabilities
            .remove(SpdmResponseCapabilityFlags::PSK_CAP_WITH_CONTEXT);
        rsp_config_info
            .rsp_capabilities
            .remove(SpdmResponseCapabilityFlags::PSK_CAP_WITHOUT_CONTEXT);

        let (mut requester, responder) = setup_requester_responder_pair(
            req_config_info,
            req_provision_info,
            rsp_config_info,
            rsp_provision_info,
        );

        let mut transcript_vca = None;
        requester
            .init_connection(&mut transcript_vca)
            .await
            .expect("capability negotiation should succeed without PSK");

        assert!(
            !requester
                .common
                .negotiate_info
                .req_capabilities_sel
                .contains(SpdmRequestCapabilityFlags::PSK_CAP)
        );
        assert!(
            !requester
                .common
                .negotiate_info
                .rsp_capabilities_sel
                .intersects(
                    SpdmResponseCapabilityFlags::PSK_CAP_WITH_CONTEXT
                        | SpdmResponseCapabilityFlags::PSK_CAP_WITHOUT_CONTEXT,
                )
        );

        let session_id = requester
            .start_session(
                true,
                0,
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
            )
            .await
            .expect("PSK session unexpectedly succeeds without negotiated PSK capability");

        assert!(
            requester.common.get_immutable_session_via_id(session_id).is_some(),
            "requester created a live PSK session without PSK_CAP"
        );
        assert!(
            responder
                .lock()
                .common
                .get_immutable_session_via_id(session_id)
                .is_some(),
            "responder accepted PSK_EXCHANGE without negotiated PSK capability"
        );
    };

    executor::block_on(future);
}

#[test]
#[cfg(feature = "mandatory-mut-auth")]
fn repro_mut_auth_done_leaks_across_sessions() {
    let finish_bytes = build_finish_request_bytes();
    let session_b = 0xfffcfffc;

    let mut responder_without_leak = setup_mut_auth_finish_responder();
    let mut fail_writer_buf = [0u8; spdmlib::config::MAX_SPDM_MSG_SIZE];
    let mut fail_writer = Writer::init(&mut fail_writer_buf);
    let (fail_status, fail_rsp) =
        responder_without_leak.handle_spdm_finish(session_b, &finish_bytes, &mut fail_writer);
    assert!(
        fail_status.is_ok() && fail_rsp.is_none(),
        "without any mutual-auth completion, responder should silently tear down session B"
    );
    assert!(
        responder_without_leak
            .common
            .get_immutable_session_via_id(session_b)
            .is_none(),
        "session B should be torn down when mutual auth is incomplete"
    );

    let mut responder_with_leak = setup_mut_auth_finish_responder();
    responder_with_leak.common.mut_auth_done = true;

    let mut ok_writer_buf = [0u8; spdmlib::config::MAX_SPDM_MSG_SIZE];
    let mut ok_writer = Writer::init(&mut ok_writer_buf);
    let (ok_status, ok_rsp) =
        responder_with_leak.handle_spdm_finish(session_b, &finish_bytes, &mut ok_writer);
    assert!(
        ok_rsp.is_some(),
        "session B should no longer be rejected at the mandatory-mut-auth gate once the unrelated global bit is set; status={ok_status:?}",
    );
    assert!(
        ok_status.is_err(),
        "session B should reach deeper FINISH processing once the unrelated global bit is set; status={ok_status:?} has_rsp={}",
        ok_rsp.is_some()
    );
}
