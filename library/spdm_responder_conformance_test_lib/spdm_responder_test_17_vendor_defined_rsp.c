/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_responder_test.h"
#include "library/xcena_test_utility_lib.h"
#include "industry_standard/pcidoe.h"
#include "industry_standard/pci_idekm.h"
#include "industry_standard/cxl_idekm.h"

#pragma pack(1)
typedef struct {
    uint8_t version;
    uint8_t heartbeat_period;
    uint8_t reserved[2];
    uint32_t session_id;
} spdm_vendor_defined_rsp_test_buffer_t;

// PCI
typedef enum {
    PCI_IDE_KM_KEY_SET_GO,
    PCI_IDE_KM_KEY_SET_STOP
} pci_ide_km_key_set_go_stop_t;

typedef enum {
    PCI_STREAM_DIRECTION_RX,
    PCI_STREAM_DIRECTION_TX
} pci_stream_direction_t;

typedef enum {
    PCI_SUBSTREAM_POSTED,
    PCI_SUBSTREAM_NONPOSTED,
    PCI_SUBSTREAM_COMPLETION
} pci_substream_t;

// PCI-IDE-KM Query
typedef struct {
    pci_doe_spdm_vendor_defined_request_t header;
    pci_ide_km_query_t pci_ide_km_query;
} pci_ide_km_query_test_request_t;

typedef struct {
    pci_doe_spdm_vendor_defined_response_t header;
    pci_ide_km_query_resp_t pci_ide_km_query_resp;
} pci_ide_km_query_test_response_t;

// PCI-IDE-KM Key Prog
typedef struct {
    pci_doe_spdm_vendor_defined_request_t header;
    pci_ide_km_key_prog_t pci_ide_km_key_prog;
    uint32_t key[8];
    uint32_t iv[2];
} pci_ide_km_key_prog_test_request_t;

typedef struct {
    pci_doe_spdm_vendor_defined_response_t header;
    pci_ide_km_kp_ack_t pci_ide_km_key_prog_ack;
} pci_ide_km_key_prog_test_response_t;

// PCI-IDE-KM Key Set Go/Stop
typedef struct {
    pci_doe_spdm_vendor_defined_request_t header;
    pci_ide_km_k_set_go_t pci_ide_km_key_set_go;
} pci_ide_km_key_set_go_test_request_t;

typedef struct {
    pci_doe_spdm_vendor_defined_response_t header;
    pci_ide_km_k_set_stop_t pci_ide_km_key_set_stop;
} pci_ide_km_key_set_stop_test_request_t;

typedef struct {
    pci_doe_spdm_vendor_defined_response_t header;
    pci_ide_km_k_gostop_ack_t pci_ide_km_key_set_go_stop_ack;
} pci_ide_km_key_set_go_stop_test_response_t;



// CXL
typedef enum {
    CXL_IDE_KM_KEY_SET_GO,
    CXL_IDE_KM_KEY_SET_STOP
} cxl_ide_km_key_set_go_stop_t;

typedef enum {
    CXL_STREAM_DIRECTION_RX,
    CXL_STREAM_DIRECTION_TX
} cxl_stream_direction_t;

// CXL-IDE-KM Query
typedef struct {
    pci_doe_spdm_vendor_defined_request_t header;
    cxl_ide_km_query_t cxl_ide_km_query;
} cxl_ide_km_query_test_request_t;

typedef struct {
    pci_doe_spdm_vendor_defined_response_t header;
    cxl_ide_km_query_resp_t cxl_ide_km_query_resp;
} cxl_ide_km_query_test_response_t;

// CXL-IDE-KM Key Program
typedef struct {
    pci_doe_spdm_vendor_defined_request_t header;
    cxl_ide_km_key_prog_t cxl_ide_km_key_prog;
    uint32_t key[8];
    uint32_t iv[3];
} cxl_ide_km_key_prog_test_request_t;

typedef struct {
    pci_doe_spdm_vendor_defined_response_t header;
    cxl_ide_km_kp_ack_t cxl_ide_km_key_prog_ack;
} cxl_ide_km_key_prog_test_response_t;

// CXL-IDE-KM GetKey Program
typedef struct {
    pci_doe_spdm_vendor_defined_request_t header;
    cxl_ide_km_get_key_t cxl_ide_km_get_key;
} cxl_ide_km_get_key_test_request_t;

typedef struct {
    pci_doe_spdm_vendor_defined_response_t header;
    cxl_ide_km_get_key_ack_t cxl_ide_km_get_key_ack;
    uint32_t key[8];
    uint32_t iv[3];
} cxl_ide_km_get_key_test_response_t;

// CXL-IDE-KM Key Set Go/Stop
typedef struct {
    pci_doe_spdm_vendor_defined_request_t header;
    cxl_ide_km_k_set_go_t cxl_ide_km_key_set_go;
} cxl_ide_km_key_set_go_test_request_t;

typedef struct {
    pci_doe_spdm_vendor_defined_response_t header;
    cxl_ide_km_k_set_stop_t cxl_ide_km_key_set_stop;
} cxl_ide_km_key_set_stop_test_request_t;

typedef struct {
    pci_doe_spdm_vendor_defined_response_t header;
    cxl_ide_km_k_gostop_ack_t cxl_ide_km_key_set_go_stop_ack;
} cxl_ide_km_key_set_go_stop_test_response_t;
#pragma pack()

static uint8_t m_cert_chain_buffer[SPDM_MAX_CERTIFICATE_CHAIN_SIZE];
static size_t m_cert_chain_buffer_size;

typedef enum _PAYLOAD_TYPE
{
    PAYLOAD_TYPE_REQUEST,
    PAYLOAD_TYPE_RESPONSE,
    PAYLOAD_TYPE_LOG
} PAYLOAD_TYPE;

static void print_payload(const char *payload, size_t size, PAYLOAD_TYPE type)
{
    const uint32_t header_size = 0;
    uint8_t* actual_payload = (uint8_t*)payload + header_size;
    uint32_t actual_size = size - header_size;

    if (type == PAYLOAD_TYPE_REQUEST) {
        xcena_test_record_test_message_custom("send-payload");
    } else if (type == PAYLOAD_TYPE_RESPONSE) {
        xcena_test_record_test_message_custom("recv-payload");
    } else {
    }

    for (size_t i = 0; i < actual_size; i++) {
        if (i % 16 == 0) {
            xcena_test_record_test_message_custom("\n");
        }
        xcena_test_record_test_message_custom("%02X ", actual_payload[i]);
    }
    xcena_test_record_test_message_custom("\n");
}

bool spdm_test_case_vendor_defined_rsp_setup_session (void *test_context,
                                                   spdm_version_number_t spdm_version,
                                                   bool need_session)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    libspdm_data_parameter_t parameter;
    uint32_t rsp_cap_flags;
    size_t data_size;
    uint32_t data32;
    uint16_t data16;
    uint8_t data8;
    spdm_vendor_defined_rsp_test_buffer_t *test_buffer;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;

    libspdm_zero_mem(&parameter, sizeof(parameter));

    if (spdm_version != 0) {
        parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
        libspdm_set_data(spdm_context, LIBSPDM_DATA_SPDM_VERSION, &parameter,
                         &spdm_version, sizeof(spdm_version));
    }

    data32 = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP |
             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
                     &data32, sizeof(data32));

    data8 = SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_MEASUREMENT_SPEC, &parameter,
                     &data8, sizeof(data8));
    data32 = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter,
                     &data32, sizeof(data32));
    data32 = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256 |
             SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384 |
             SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512 |
             SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256 |
             SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384 |
             SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512 |
             SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter,
                     &data32, sizeof(data32));
    data16 = SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048 |
             SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072 |
             SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096 |
             SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1 |
             SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1 |
             SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1 |
             SPDM_ALGORITHMS_DHE_NAMED_GROUP_SM2_P256;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_DHE_NAME_GROUP, &parameter,
                     &data16, sizeof(data16));
    data16 = SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM |
             SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM |
             SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305 |
             SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AEAD_SM4_GCM;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_AEAD_CIPHER_SUITE, &parameter,
                     &data16, sizeof(data16));
    data16 = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519 |
             SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter,
                     &data16, sizeof(data16));
    data16 = SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_KEY_SCHEDULE, &parameter, &data16,
                     sizeof(data16));
    data8 = SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_OTHER_PARAMS_SUPPORT, &parameter,
                     &data8, sizeof(data8));

    status = libspdm_init_connection (spdm_context, false);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return false;
    }

    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(sizeof(spdm_test_context->test_scratch_buffer) >=
                   sizeof(spdm_vendor_defined_rsp_test_buffer_t));
    libspdm_zero_mem(test_buffer, sizeof(spdm_vendor_defined_rsp_test_buffer_t));
    spdm_test_context->test_scratch_buffer_size = sizeof(spdm_vendor_defined_rsp_test_buffer_t);

    spdm_version = 0;
    data_size = sizeof(spdm_version);
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    libspdm_get_data(spdm_context, LIBSPDM_DATA_SPDM_VERSION, &parameter, &spdm_version,
                     &data_size);
    test_buffer->version = (spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT);

    rsp_cap_flags = 0;
    data_size = sizeof(rsp_cap_flags);
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    libspdm_get_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter, &rsp_cap_flags,
                     &data_size);
    if ((rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP) == 0) {
        return false;
    }

    if (((rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP) == 0) ||
        ((rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP) == 0)) {
        return false;
    }

    m_cert_chain_buffer_size = sizeof(m_cert_chain_buffer);
    status = libspdm_get_certificate (spdm_context, NULL, 0,
                                      &m_cert_chain_buffer_size, m_cert_chain_buffer);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return false;
    }

    if (need_session) {
        status = libspdm_start_session (spdm_context, false, NULL, 0,
                                        SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                                        0, 0, &test_buffer->session_id,
                                        &test_buffer->heartbeat_period, NULL);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return false;
        }
    }

    return true;
}

bool spdm_test_case_vendor_defined_rsp_setup_version_any (void *test_context)
{
    return spdm_test_case_vendor_defined_rsp_setup_session (test_context, 0, true);
}

bool spdm_test_case_vendor_defined_rsp_setup_version_any_session_cap (void *test_context)
{
    return spdm_test_case_vendor_defined_rsp_setup_session (test_context, 0, false);
}

bool spdm_test_case_vendor_defined_rsp_cxl_ide_km_query_success (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    cxl_ide_km_query_test_request_t spdm_request;
    cxl_ide_km_query_test_response_t *spdm_response;
    uint8_t message[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t spdm_response_size;
    common_test_result_t test_result = COMMON_TEST_RESULT_PASS;
    spdm_vendor_defined_rsp_test_buffer_t *test_buffer;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(spdm_test_context->test_scratch_buffer_size ==
                   sizeof(spdm_vendor_defined_rsp_test_buffer_t));

    // Construct a CXL-IDE-KM Query request
    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_header.spdm_version = test_buffer->version;
    spdm_request.header.spdm_header.request_response_code = SPDM_VENDOR_DEFINED_REQUEST;
    spdm_request.header.spdm_header.param1 = 0;
    spdm_request.header.spdm_header.param2 = 0;
    spdm_request.header.pci_doe_vendor_header.standard_id = SPDM_STANDARD_ID_CXL;
    spdm_request.header.pci_doe_vendor_header.len = sizeof(spdm_request.header.pci_doe_vendor_header.vendor_id);
    spdm_request.header.pci_doe_vendor_header.vendor_id = SPDM_VENDOR_ID_CXL;
    spdm_request.header.pci_doe_vendor_header.payload_length =
        sizeof(spdm_request.header.pci_doe_vendor_header.pci_protocol) +
        sizeof(spdm_request.cxl_ide_km_query);
    spdm_request.header.pci_doe_vendor_header.pci_protocol.protocol_id = CXL_PROTOCOL_ID_IDE_KM;
    spdm_request.cxl_ide_km_query.header.object_id = CXL_IDE_KM_OBJECT_ID_QUERY;
    spdm_request.cxl_ide_km_query.reserved = 0;
    spdm_request.cxl_ide_km_query.port_index = 0;

    xcena_test_record_test_message_custom("\n### cxl_ide_km_query\n");
    print_payload((const char *)&spdm_request, sizeof(spdm_request), PAYLOAD_TYPE_REQUEST);

    // Run the CXL-IDE-KM Query request
    spdm_response = (void *)message;
    spdm_response_size = sizeof(message);
    libspdm_zero_mem(message, sizeof(message));
    status = libspdm_send_receive_data(spdm_context, &test_buffer->session_id, false,
                                       &spdm_request, sizeof(spdm_request),
                                       spdm_response, &spdm_response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        xcena_test_record_test_assertion_custom_print(
            COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
        return false;
    }

    // Verify the response
    print_payload((const char *)spdm_response, spdm_response_size, PAYLOAD_TYPE_RESPONSE);

    test_result = COMMON_TEST_RESULT_PASS;
    bool is_valid_response = false;

    do
    {
        // minimum response size
        if (spdm_response_size < sizeof(*spdm_response)) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response size - %d", spdm_response_size);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // SPDM version
        if (spdm_response->header.spdm_header.spdm_version != test_buffer->version) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response version - 0x%02x", spdm_response->header.spdm_header.spdm_version);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // SPDM request response code
        if (spdm_response->header.spdm_header.request_response_code != SPDM_VENDOR_DEFINED_RESPONSE) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response code - 0x%02x", spdm_response->header.spdm_header.request_response_code);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // SPDM param1 & param2
        if ((spdm_response->header.spdm_header.param1 != 0) ||
            (spdm_response->header.spdm_header.param2 != 0)) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response param1 - 0x%02x, param2 - 0x%02x",
            spdm_response->header.spdm_header.param1, spdm_response->header.spdm_header.param2);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // Standard ID
        if (spdm_response->header.pci_doe_vendor_header.standard_id != SPDM_STANDARD_ID_CXL) {
            test_result = COMMON_TEST_RESULT_PASS;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response standard_id - 0x%02x", spdm_response->header.pci_doe_vendor_header.standard_id);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // Vendor ID
        if (spdm_response->header.pci_doe_vendor_header.vendor_id != SPDM_VENDOR_ID_CXL) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response vendor_id - 0x%02x", spdm_response->header.pci_doe_vendor_header.vendor_id);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // Payload length
        if (spdm_response->header.pci_doe_vendor_header.payload_length <
            sizeof(spdm_response->header.pci_doe_vendor_header.pci_protocol) +
            sizeof(spdm_response->cxl_ide_km_query_resp)) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response payload_length - 0x%02x", spdm_response->header.pci_doe_vendor_header.payload_length);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // Protocol ID
        if (spdm_response->header.pci_doe_vendor_header.pci_protocol.protocol_id != CXL_PROTOCOL_ID_IDE_KM) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response protocol_id - 0x%02x", spdm_response->header.pci_doe_vendor_header.pci_protocol.protocol_id);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // CXL-IDE-KM Query Response
        if (spdm_response->cxl_ide_km_query_resp.header.object_id != CXL_IDE_KM_OBJECT_ID_QUERY_RESP) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response object_id - 0x%02x", spdm_response->cxl_ide_km_query_resp.header.object_id);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // Capability version
        if (((spdm_response->cxl_ide_km_query_resp.caps & CXL_IDE_KM_QUERY_RESP_CAP_VERSION_MASK)
                != CXL_IDE_KM_QUERY_RESP_CAP_VERSION_1) ||
            ((spdm_response->cxl_ide_km_query_resp.caps & CXL_IDE_KM_QUERY_RESP_IV_GEN_CAP_MASK)
                != CXL_IDE_KM_QUERY_RESP_IV_GEN_CAP) ||
            ((spdm_response->cxl_ide_km_query_resp.caps & CXL_IDE_KM_QUERY_RESP_KEY_GEN_CAP_MASK)
                != CXL_IDE_KM_QUERY_RESP_KEY_GEN_CAP) ||
            ((spdm_response->cxl_ide_km_query_resp.caps & CXL_IDE_KM_QUERY_RESP_K_SET_STOP_CAP_MASK)
                != CXL_IDE_KM_QUERY_RESP_K_SET_STOP_CAP)) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response caps - 0x%02x", spdm_response->cxl_ide_km_query_resp.caps);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // IDE register
        uint32_t ide_reg_count = (uint32_t)(spdm_response_size - sizeof(*spdm_response)) / sizeof(uint32_t);
        if (spdm_response_size != sizeof(*spdm_response) + ide_reg_count * sizeof(uint32_t)) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response ide_reg_count - 0x%02x", ide_reg_count);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        is_valid_response = true;
    } while (false);

    return is_valid_response;
}

bool spdm_test_case_vendor_defined_rsp_cxl_ide_km_key_prog_tx_success (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    cxl_ide_km_key_prog_test_request_t spdm_request;
    cxl_ide_km_key_prog_test_response_t *spdm_response;
    uint8_t message[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t spdm_response_size;
    common_test_result_t test_result = COMMON_TEST_RESULT_PASS;
    spdm_vendor_defined_rsp_test_buffer_t *test_buffer;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(spdm_test_context->test_scratch_buffer_size ==
                   sizeof(spdm_vendor_defined_rsp_test_buffer_t));

    // Construct a CXL-IDE-KM Key Prog request
    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_header.spdm_version = test_buffer->version;
    spdm_request.header.spdm_header.request_response_code = SPDM_VENDOR_DEFINED_REQUEST;
    spdm_request.header.spdm_header.param1 = 0;
    spdm_request.header.spdm_header.param2 = 0;
    spdm_request.header.pci_doe_vendor_header.standard_id = SPDM_STANDARD_ID_CXL;
    spdm_request.header.pci_doe_vendor_header.len = sizeof(spdm_request.header.pci_doe_vendor_header.vendor_id);
    spdm_request.header.pci_doe_vendor_header.vendor_id = SPDM_VENDOR_ID_CXL;
    spdm_request.header.pci_doe_vendor_header.payload_length =
        sizeof(spdm_request.header.pci_doe_vendor_header.pci_protocol) +
        sizeof(spdm_request.cxl_ide_km_key_prog) +
        sizeof(spdm_request.iv) +
        sizeof(spdm_request.key);
    spdm_request.header.pci_doe_vendor_header.pci_protocol.protocol_id = CXL_PROTOCOL_ID_IDE_KM;
    spdm_request.cxl_ide_km_key_prog.header.object_id = CXL_IDE_KM_OBJECT_ID_KEY_PROG;
    spdm_request.cxl_ide_km_key_prog.port_index = 0;
    spdm_request.cxl_ide_km_key_prog.stream_id = 0;
    spdm_request.cxl_ide_km_key_prog.key_sub_stream = CXL_IDE_KM_KEY_DIRECTION_TX |
                                                      CXL_IDE_KM_KEY_IV_INITIAL |
                                                      CXL_IDE_KM_KEY_SUB_STREAM_CXL;
    spdm_request.cxl_ide_km_key_prog.port_index = 0;
    spdm_request.iv[0] = 0x80000000;
    spdm_request.iv[1] = 0;
    spdm_request.iv[2] = 1;
    libspdm_get_random_number(sizeof(spdm_request.key), (void *)spdm_request.key);

    xcena_test_record_test_message_custom("\n### cxl_ide_km_key_prog for tx\n");
    print_payload((const char *)&spdm_request, sizeof(spdm_request), PAYLOAD_TYPE_REQUEST);

    // Run the CXL-IDE-KM Key Prog request
    spdm_response = (void *)message;
    spdm_response_size = sizeof(message);
    libspdm_zero_mem(message, sizeof(message));
    status = libspdm_send_receive_data(spdm_context, &test_buffer->session_id, false,
                                       &spdm_request, sizeof(spdm_request),
                                       spdm_response, &spdm_response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        xcena_test_record_test_assertion_custom_print(
            COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
        return false;
    }

    // Verify the response
    print_payload((const char *)spdm_response, spdm_response_size, PAYLOAD_TYPE_RESPONSE);

    test_result = COMMON_TEST_RESULT_PASS;
    bool is_valid_response = false;

    do
    {
        // minimum response size
        if (spdm_response_size < sizeof(*spdm_response)) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response size - %d", spdm_response_size);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // SPDM version
        if (spdm_response->header.spdm_header.spdm_version != test_buffer->version) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response version - 0x%02x", spdm_response->header.spdm_header.spdm_version);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // SPDM request response code
        if (spdm_response->header.spdm_header.request_response_code != SPDM_VENDOR_DEFINED_RESPONSE) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response code - 0x%02x", spdm_response->header.spdm_header.request_response_code);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // SPDM param1 & param2
        if ((spdm_response->header.spdm_header.param1 != 0) ||
            (spdm_response->header.spdm_header.param2 != 0)) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response param1 - 0x%02x, param2 - 0x%02x",
            spdm_response->header.spdm_header.param1, spdm_response->header.spdm_header.param2);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // Standard ID
        if (spdm_response->header.pci_doe_vendor_header.standard_id != SPDM_STANDARD_ID_CXL) {
            test_result = COMMON_TEST_RESULT_PASS;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response standard_id - 0x%02x", spdm_response->header.pci_doe_vendor_header.standard_id);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // Vendor ID
        if (spdm_response->header.pci_doe_vendor_header.vendor_id != SPDM_VENDOR_ID_CXL) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response vendor_id - 0x%02x", spdm_response->header.pci_doe_vendor_header.vendor_id);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // Payload length
        if (spdm_response->header.pci_doe_vendor_header.payload_length <
            sizeof(spdm_response->header.pci_doe_vendor_header.pci_protocol) +
            sizeof(spdm_response->cxl_ide_km_key_prog_ack)) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response payload_length - 0x%02x", spdm_response->header.pci_doe_vendor_header.payload_length);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // Protocol ID
        if (spdm_response->header.pci_doe_vendor_header.pci_protocol.protocol_id != CXL_PROTOCOL_ID_IDE_KM) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response protocol_id - 0x%02x", spdm_response->header.pci_doe_vendor_header.pci_protocol.protocol_id);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // CXL-IDE-KM Key Prog Response
        if (spdm_response->cxl_ide_km_key_prog_ack.header.object_id != CXL_IDE_KM_OBJECT_ID_KP_ACK) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response object_id - 0x%02x", spdm_response->cxl_ide_km_key_prog_ack.header.object_id);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        is_valid_response = true;
    } while (false);

    return is_valid_response;
}

bool spdm_test_case_vendor_defined_rsp_cxl_ide_km_key_prog_rx_success (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    cxl_ide_km_key_prog_test_request_t spdm_request;
    cxl_ide_km_key_prog_test_response_t *spdm_response;
    cxl_ide_km_get_key_test_request_t spdm_get_key_request;
    cxl_ide_km_get_key_test_response_t *spdm_get_key_response;
    uint8_t message[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t spdm_response_size;
    common_test_result_t test_result = COMMON_TEST_RESULT_PASS;
    spdm_vendor_defined_rsp_test_buffer_t *test_buffer;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(spdm_test_context->test_scratch_buffer_size ==
                   sizeof(spdm_vendor_defined_rsp_test_buffer_t));

    // Construct a CXL-IDE-KM Get Key request
    libspdm_zero_mem(&spdm_get_key_request, sizeof(spdm_get_key_request));
    spdm_get_key_request.header.spdm_header.spdm_version = test_buffer->version;
    spdm_get_key_request.header.spdm_header.request_response_code = SPDM_VENDOR_DEFINED_REQUEST;
    spdm_get_key_request.header.spdm_header.param1 = 0;
    spdm_get_key_request.header.spdm_header.param2 = 0;
    spdm_get_key_request.header.pci_doe_vendor_header.standard_id = SPDM_STANDARD_ID_CXL;
    spdm_get_key_request.header.pci_doe_vendor_header.len = sizeof(spdm_get_key_request.header.pci_doe_vendor_header.vendor_id);
    spdm_get_key_request.header.pci_doe_vendor_header.vendor_id = SPDM_VENDOR_ID_CXL;
    spdm_get_key_request.header.pci_doe_vendor_header.payload_length =
        sizeof(spdm_get_key_request.header.pci_doe_vendor_header.pci_protocol) +
        sizeof(spdm_get_key_request.cxl_ide_km_get_key);
    spdm_get_key_request.header.pci_doe_vendor_header.pci_protocol.protocol_id = CXL_PROTOCOL_ID_IDE_KM;
    spdm_get_key_request.cxl_ide_km_get_key.header.object_id = CXL_IDE_KM_OBJECT_ID_GET_KEY;
    spdm_get_key_request.cxl_ide_km_get_key.stream_id = 0;
    spdm_get_key_request.cxl_ide_km_get_key.key_sub_stream = CXL_IDE_KM_KEY_SUB_STREAM_CXL;
    spdm_get_key_request.cxl_ide_km_get_key.port_index = 0;

    xcena_test_record_test_message_custom("\n### cxl_ide_km_get_key\n");
    print_payload((const char *)&spdm_get_key_request, sizeof(spdm_get_key_request), PAYLOAD_TYPE_REQUEST);

    // Run the CXL-IDE-KM Get Key request
    spdm_get_key_response = (void *)message;
    spdm_response_size = sizeof(message);
    libspdm_zero_mem(message, sizeof(message));
    status = libspdm_send_receive_data(spdm_context, &test_buffer->session_id, false,
                                       &spdm_get_key_request, sizeof(spdm_get_key_request),
                                       spdm_get_key_response, &spdm_response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        xcena_test_record_test_assertion_custom_print(
            COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
        return false;
    }

    // Verify the response
    print_payload((const char *)spdm_get_key_response, spdm_response_size, PAYLOAD_TYPE_RESPONSE);

    test_result = COMMON_TEST_RESULT_PASS;
    bool is_valid_response = false;

    do
    {
        // minimum response size
        if (spdm_response_size < sizeof(*spdm_get_key_response)) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response size - %d", spdm_response_size);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // SPDM version
        if (spdm_get_key_response->header.spdm_header.spdm_version != test_buffer->version) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response version - 0x%02x", spdm_get_key_response->header.spdm_header.spdm_version);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // SPDM request response code
        if (spdm_get_key_response->header.spdm_header.request_response_code != SPDM_VENDOR_DEFINED_RESPONSE) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response code - 0x%02x", spdm_get_key_response->header.spdm_header.request_response_code);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // SPDM param1 & param2
        if ((spdm_get_key_response->header.spdm_header.param1 != 0) ||
            (spdm_get_key_response->header.spdm_header.param2 != 0)) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response param1 - 0x%02x, param2 - 0x%02x",
            spdm_get_key_response->header.spdm_header.param1, spdm_get_key_response->header.spdm_header.param2);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // Standard ID
        if (spdm_get_key_response->header.pci_doe_vendor_header.standard_id != SPDM_STANDARD_ID_CXL) {
            test_result = COMMON_TEST_RESULT_PASS;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response standard_id - 0x%02x", spdm_get_key_response->header.pci_doe_vendor_header.standard_id);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // Vendor ID
        if (spdm_get_key_response->header.pci_doe_vendor_header.vendor_id != SPDM_VENDOR_ID_CXL) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response vendor_id - 0x%02x", spdm_get_key_response->header.pci_doe_vendor_header.vendor_id);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // Payload length
        if (spdm_get_key_response->header.pci_doe_vendor_header.payload_length <
            sizeof(spdm_get_key_response->header.pci_doe_vendor_header.pci_protocol) +
            sizeof(spdm_get_key_response->cxl_ide_km_get_key_ack)) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response payload_length - 0x%02x", spdm_get_key_response->header.pci_doe_vendor_header.payload_length);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // Protocol ID
        if (spdm_get_key_response->header.pci_doe_vendor_header.pci_protocol.protocol_id != CXL_PROTOCOL_ID_IDE_KM) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response protocol_id - 0x%02x", spdm_get_key_response->header.pci_doe_vendor_header.pci_protocol.protocol_id);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // CXL-IDE-KM Key Prog Response
        if (spdm_get_key_response->cxl_ide_km_get_key_ack.header.object_id != CXL_IDE_KM_OBJECT_ID_GET_KEY_ACK) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response object_id - 0x%02x", spdm_get_key_response->cxl_ide_km_get_key_ack.header.object_id);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        is_valid_response = true;
    } while (false);

    if (is_valid_response == false) {
        return false;
    }

    uint32_t key[8];
    uint32_t iv[3];

    memcpy(key, spdm_get_key_response->key, sizeof(key));
    memcpy(iv, spdm_get_key_response->iv, sizeof(iv));

    // Construct a CXL-IDE-KM Key Prog request
    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_header.spdm_version = test_buffer->version;
    spdm_request.header.spdm_header.request_response_code = SPDM_VENDOR_DEFINED_REQUEST;
    spdm_request.header.spdm_header.param1 = 0;
    spdm_request.header.spdm_header.param2 = 0;
    spdm_request.header.pci_doe_vendor_header.standard_id = SPDM_STANDARD_ID_CXL;
    spdm_request.header.pci_doe_vendor_header.len = sizeof(spdm_request.header.pci_doe_vendor_header.vendor_id);
    spdm_request.header.pci_doe_vendor_header.vendor_id = SPDM_VENDOR_ID_CXL;
    spdm_request.header.pci_doe_vendor_header.payload_length =
        sizeof(spdm_request.header.pci_doe_vendor_header.pci_protocol) +
        sizeof(spdm_request.cxl_ide_km_key_prog) +
        sizeof(spdm_request.iv) +
        sizeof(spdm_request.key);
    spdm_request.header.pci_doe_vendor_header.pci_protocol.protocol_id = CXL_PROTOCOL_ID_IDE_KM;
    spdm_request.cxl_ide_km_key_prog.header.object_id = CXL_IDE_KM_OBJECT_ID_KEY_PROG;
    spdm_request.cxl_ide_km_key_prog.port_index = 0;
    spdm_request.cxl_ide_km_key_prog.stream_id = 0;
    spdm_request.cxl_ide_km_key_prog.key_sub_stream = CXL_IDE_KM_KEY_DIRECTION_RX |
                                                      CXL_IDE_KM_KEY_IV_DEFAULT |
                                                      CXL_IDE_KM_KEY_SUB_STREAM_CXL;
    spdm_request.cxl_ide_km_key_prog.port_index = 0;
    memcpy(spdm_request.key, key, sizeof(key));
    memcpy(spdm_request.iv, iv, sizeof(iv));

    xcena_test_record_test_message_custom("\n### cxl_ide_km_key_prog for rx\n");
    print_payload((const char *)&spdm_request, sizeof(spdm_request), PAYLOAD_TYPE_REQUEST);

    // Run the cxl-ide-km query request
    spdm_response = (void *)message;
    spdm_response_size = sizeof(message);
    libspdm_zero_mem(message, sizeof(message));
    status = libspdm_send_receive_data(spdm_context, &test_buffer->session_id, false,
                                       &spdm_request, sizeof(spdm_request),
                                       spdm_response, &spdm_response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        xcena_test_record_test_assertion_custom_print(
            COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
        return false;
    }

    // Verify the response
    print_payload((const char *)spdm_response, spdm_response_size, PAYLOAD_TYPE_RESPONSE);

    test_result = COMMON_TEST_RESULT_PASS;
    is_valid_response = false;

    do
    {
        // minimum response size
        if (spdm_response_size < sizeof(*spdm_response)) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response size - %d", spdm_response_size);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // SPDM version
        if (spdm_response->header.spdm_header.spdm_version != test_buffer->version) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response version - 0x%02x", spdm_response->header.spdm_header.spdm_version);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // SPDM request response code
        if (spdm_response->header.spdm_header.request_response_code != SPDM_VENDOR_DEFINED_RESPONSE) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response code - 0x%02x", spdm_response->header.spdm_header.request_response_code);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // SPDM param1 & param2
        if ((spdm_response->header.spdm_header.param1 != 0) ||
            (spdm_response->header.spdm_header.param2 != 0)) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response param1 - 0x%02x, param2 - 0x%02x",
            spdm_response->header.spdm_header.param1, spdm_response->header.spdm_header.param2);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // Standard ID
        if (spdm_response->header.pci_doe_vendor_header.standard_id != SPDM_STANDARD_ID_CXL) {
            test_result = COMMON_TEST_RESULT_PASS;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response standard_id - 0x%02x", spdm_response->header.pci_doe_vendor_header.standard_id);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // Vendor ID
        if (spdm_response->header.pci_doe_vendor_header.vendor_id != SPDM_VENDOR_ID_CXL) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response vendor_id - 0x%02x", spdm_response->header.pci_doe_vendor_header.vendor_id);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // Payload length
        if (spdm_response->header.pci_doe_vendor_header.payload_length <
            sizeof(spdm_response->header.pci_doe_vendor_header.pci_protocol) +
            sizeof(spdm_response->cxl_ide_km_key_prog_ack)) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response payload_length - 0x%02x", spdm_response->header.pci_doe_vendor_header.payload_length);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // Protocol ID
        if (spdm_response->header.pci_doe_vendor_header.pci_protocol.protocol_id != CXL_PROTOCOL_ID_IDE_KM) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response protocol_id - 0x%02x", spdm_response->header.pci_doe_vendor_header.pci_protocol.protocol_id);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // CXL-IDE-KM Key Prog Response
        if (spdm_response->cxl_ide_km_key_prog_ack.header.object_id != CXL_IDE_KM_OBJECT_ID_KP_ACK) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response object_id - 0x%02x", spdm_response->cxl_ide_km_key_prog_ack.header.object_id);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        is_valid_response = true;
    } while (false);

    return is_valid_response;
}

bool spdm_test_case_vendor_defined_rsp_cxl_ide_km_key_set_go_stop_success (void *test_context,
                                                                      cxl_stream_direction_t direction,
                                                                      cxl_ide_km_key_set_go_stop_t gostop)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    cxl_ide_km_key_set_go_test_request_t spdm_request;
    cxl_ide_km_key_set_go_stop_test_response_t *spdm_response;
    uint8_t message[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t spdm_response_size;
    common_test_result_t test_result = COMMON_TEST_RESULT_PASS;
    spdm_vendor_defined_rsp_test_buffer_t *test_buffer;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(spdm_test_context->test_scratch_buffer_size ==
                   sizeof(spdm_vendor_defined_rsp_test_buffer_t));

    // Construct a CXL-IDE-KM Key Set Go request
    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_header.spdm_version = test_buffer->version;
    spdm_request.header.spdm_header.request_response_code = SPDM_VENDOR_DEFINED_REQUEST;
    spdm_request.header.spdm_header.param1 = 0;
    spdm_request.header.spdm_header.param2 = 0;
    spdm_request.header.pci_doe_vendor_header.standard_id = SPDM_STANDARD_ID_CXL;
    spdm_request.header.pci_doe_vendor_header.len = sizeof(spdm_request.header.pci_doe_vendor_header.vendor_id);
    spdm_request.header.pci_doe_vendor_header.vendor_id = SPDM_VENDOR_ID_CXL;
    spdm_request.header.pci_doe_vendor_header.payload_length =
        sizeof(spdm_request.header.pci_doe_vendor_header.pci_protocol) +
        sizeof(spdm_request.cxl_ide_km_key_set_go);
    spdm_request.header.pci_doe_vendor_header.pci_protocol.protocol_id = CXL_PROTOCOL_ID_IDE_KM;
    spdm_request.cxl_ide_km_key_set_go.header.object_id = (gostop == CXL_IDE_KM_KEY_SET_GO) ?
                                                          CXL_IDE_KM_OBJECT_ID_K_SET_GO : CXL_IDE_KM_OBJECT_ID_K_SET_STOP;
    spdm_request.cxl_ide_km_key_set_go.port_index = 0;
    spdm_request.cxl_ide_km_key_set_go.stream_id = 0;
    spdm_request.cxl_ide_km_key_set_go.key_sub_stream = ((direction == CXL_STREAM_DIRECTION_RX) ?
                                                        CXL_IDE_KM_KEY_DIRECTION_RX : CXL_IDE_KM_KEY_DIRECTION_TX) |
                                                        CXL_IDE_KM_KEY_MODE_SKID |
                                                        CXL_IDE_KM_KEY_SUB_STREAM_CXL;

    xcena_test_record_test_message_custom("\n### cxl_ide_km_key_set_%s for %s\n",
                                           (gostop == CXL_IDE_KM_KEY_SET_GO) ? "go" : "stop",
                                           (direction == CXL_STREAM_DIRECTION_RX) ? "rx" : "tx");
    print_payload((const char *)&spdm_request, sizeof(spdm_request), PAYLOAD_TYPE_REQUEST);

    // Run the CXL-IDE-KM Key Prog request
    spdm_response = (void *)message;
    spdm_response_size = sizeof(message);
    libspdm_zero_mem(message, sizeof(message));
    status = libspdm_send_receive_data(spdm_context, &test_buffer->session_id, false,
                                       &spdm_request, sizeof(spdm_request),
                                       spdm_response, &spdm_response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        xcena_test_record_test_assertion_custom_print(
            COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
        return false;
    }

    // Verify the response
    print_payload((const char *)spdm_response, spdm_response_size, PAYLOAD_TYPE_RESPONSE);

    test_result = COMMON_TEST_RESULT_PASS;
    bool is_valid_response = false;

    do
    {
        // minimum response size
        if (spdm_response_size < sizeof(*spdm_response)) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response size - %d", spdm_response_size);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // SPDM version
        if (spdm_response->header.spdm_header.spdm_version != test_buffer->version) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response version - 0x%02x", spdm_response->header.spdm_header.spdm_version);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // SPDM request response code
        if (spdm_response->header.spdm_header.request_response_code != SPDM_VENDOR_DEFINED_RESPONSE) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response code - 0x%02x", spdm_response->header.spdm_header.request_response_code);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // SPDM param1 & param2
        if ((spdm_response->header.spdm_header.param1 != 0) ||
            (spdm_response->header.spdm_header.param2 != 0)) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response param1 - 0x%02x, param2 - 0x%02x",
            spdm_response->header.spdm_header.param1, spdm_response->header.spdm_header.param2);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // Standard ID
        if (spdm_response->header.pci_doe_vendor_header.standard_id != SPDM_STANDARD_ID_CXL) {
            test_result = COMMON_TEST_RESULT_PASS;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response standard_id - 0x%02x", spdm_response->header.pci_doe_vendor_header.standard_id);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // Vendor ID
        if (spdm_response->header.pci_doe_vendor_header.vendor_id != SPDM_VENDOR_ID_CXL) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response vendor_id - 0x%02x", spdm_response->header.pci_doe_vendor_header.vendor_id);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // Payload length
        if (spdm_response->header.pci_doe_vendor_header.payload_length <
            sizeof(spdm_response->header.pci_doe_vendor_header.pci_protocol) +
            sizeof(spdm_response->cxl_ide_km_key_set_go_stop_ack)) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response payload_length - 0x%02x", spdm_response->header.pci_doe_vendor_header.payload_length);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // Protocol ID
        if (spdm_response->header.pci_doe_vendor_header.pci_protocol.protocol_id != CXL_PROTOCOL_ID_IDE_KM) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response protocol_id - 0x%02x", spdm_response->header.pci_doe_vendor_header.pci_protocol.protocol_id);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // CXL-IDE-KM Key Prog Response
        if (spdm_response->cxl_ide_km_key_set_go_stop_ack.header.object_id != CXL_IDE_KM_OBJECT_ID_K_SET_GOSTOP_ACK) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response object_id - 0x%02x", spdm_response->cxl_ide_km_key_set_go_stop_ack.header.object_id);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        is_valid_response = true;
    } while (false);

    return is_valid_response;
}

void spdm_test_case_vendor_defined_rsp_cxl_ide_km_success (void *test_context)
{
    xcena_test_record_test_assertion_custom_set(
        SPDM_RESPONDER_TEST_GROUP_VENDOR_DEFINED_RSP,
        SPDM_RESPONDER_TEST_CASE_VENDOR_DEFINED_RSP_CXL_IDE_KM_SUCCESS);

    if (false == spdm_test_case_vendor_defined_rsp_cxl_ide_km_query_success(test_context)) {
        return;
    }
    
    if (false == spdm_test_case_vendor_defined_rsp_cxl_ide_km_key_prog_tx_success(test_context)) {
        return;
    }

    if (false == spdm_test_case_vendor_defined_rsp_cxl_ide_km_key_prog_rx_success(test_context)) {
        return;
    }

    if (false == spdm_test_case_vendor_defined_rsp_cxl_ide_km_key_set_go_stop_success(test_context, CXL_STREAM_DIRECTION_RX, CXL_IDE_KM_KEY_SET_GO)) {
        return;
    }

    if (false == spdm_test_case_vendor_defined_rsp_cxl_ide_km_key_set_go_stop_success(test_context, CXL_STREAM_DIRECTION_TX, CXL_IDE_KM_KEY_SET_GO)) {
        return;
    }

    if (false == spdm_test_case_vendor_defined_rsp_cxl_ide_km_key_set_go_stop_success(test_context, CXL_STREAM_DIRECTION_RX, CXL_IDE_KM_KEY_SET_STOP)) {
        return;
    }

    if (false == spdm_test_case_vendor_defined_rsp_cxl_ide_km_key_set_go_stop_success(test_context, CXL_STREAM_DIRECTION_TX, CXL_IDE_KM_KEY_SET_STOP)) {
        return;
    }
}

void spdm_test_case_vendor_defined_rsp_cxl_tsp_success (void *test_context)
{
    xcena_test_record_test_assertion_custom_set(
        SPDM_RESPONDER_TEST_GROUP_VENDOR_DEFINED_RSP,
        SPDM_RESPONDER_TEST_CASE_VENDOR_DEFINED_RSP_CXL_TSP_SUCCESS);
}

bool spdm_test_case_vendor_defined_rsp_pci_ide_km_query_success (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    pci_ide_km_query_test_request_t spdm_request;
    pci_ide_km_query_test_response_t *spdm_response;
    uint8_t message[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t spdm_response_size;
    common_test_result_t test_result = COMMON_TEST_RESULT_PASS;
    spdm_vendor_defined_rsp_test_buffer_t *test_buffer;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(spdm_test_context->test_scratch_buffer_size ==
                   sizeof(spdm_vendor_defined_rsp_test_buffer_t));

    // Construct a CXL-IDE-KM Query request
    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_header.spdm_version = test_buffer->version;
    spdm_request.header.spdm_header.request_response_code = SPDM_VENDOR_DEFINED_REQUEST;
    spdm_request.header.spdm_header.param1 = 0;
    spdm_request.header.spdm_header.param2 = 0;
    spdm_request.header.pci_doe_vendor_header.standard_id = SPDM_STANDARD_ID_PCISIG;
    spdm_request.header.pci_doe_vendor_header.len = sizeof(spdm_request.header.pci_doe_vendor_header.vendor_id);
    spdm_request.header.pci_doe_vendor_header.vendor_id = SPDM_VENDOR_ID_PCISIG;
    spdm_request.header.pci_doe_vendor_header.payload_length =
        sizeof(spdm_request.header.pci_doe_vendor_header.pci_protocol) +
        sizeof(spdm_request.pci_ide_km_query);
    spdm_request.header.pci_doe_vendor_header.pci_protocol.protocol_id = PCI_PROTOCOL_ID_IDE_KM;
    spdm_request.pci_ide_km_query.header.object_id = PCI_IDE_KM_OBJECT_ID_QUERY;
    spdm_request.pci_ide_km_query.reserved = 0;
    spdm_request.pci_ide_km_query.port_index = 0;

    xcena_test_record_test_message_custom("\n### pci_ide_km_query\n");
    print_payload((const char *)&spdm_request, sizeof(spdm_request), PAYLOAD_TYPE_REQUEST);

    // Run the PCI-IDE-KM Query request
    spdm_response = (void *)message;
    spdm_response_size = sizeof(message);
    libspdm_zero_mem(message, sizeof(message));
    status = libspdm_send_receive_data(spdm_context, &test_buffer->session_id, false,
                                       &spdm_request, sizeof(spdm_request),
                                       spdm_response, &spdm_response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        xcena_test_record_test_assertion_custom_print(
            COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
        return false;
    }

    // Verify the response
    print_payload((const char *)spdm_response, spdm_response_size, PAYLOAD_TYPE_RESPONSE);

    test_result = COMMON_TEST_RESULT_PASS;
    bool is_valid_response = false;

    do
    {
        // minimum response size
        if (spdm_response_size < sizeof(*spdm_response)) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response size - %d", spdm_response_size);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // SPDM version
        if (spdm_response->header.spdm_header.spdm_version != test_buffer->version) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response version - 0x%02x", spdm_response->header.spdm_header.spdm_version);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // SPDM request response code
        if (spdm_response->header.spdm_header.request_response_code != SPDM_VENDOR_DEFINED_RESPONSE) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response code - 0x%02x", spdm_response->header.spdm_header.request_response_code);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // SPDM param1 & param2
        if ((spdm_response->header.spdm_header.param1 != 0) ||
            (spdm_response->header.spdm_header.param2 != 0)) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response param1 - 0x%02x, param2 - 0x%02x",
            spdm_response->header.spdm_header.param1, spdm_response->header.spdm_header.param2);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // Standard ID
        if (spdm_response->header.pci_doe_vendor_header.standard_id != SPDM_STANDARD_ID_PCISIG) {
            test_result = COMMON_TEST_RESULT_PASS;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response standard_id - 0x%02x", spdm_response->header.pci_doe_vendor_header.standard_id);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // Vendor ID
        if (spdm_response->header.pci_doe_vendor_header.vendor_id != SPDM_VENDOR_ID_PCISIG) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response vendor_id - 0x%02x", spdm_response->header.pci_doe_vendor_header.vendor_id);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // Payload length
        if (spdm_response->header.pci_doe_vendor_header.payload_length <
            sizeof(spdm_response->header.pci_doe_vendor_header.pci_protocol) +
            sizeof(spdm_response->pci_ide_km_query_resp)) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response payload_length - 0x%02x", spdm_response->header.pci_doe_vendor_header.payload_length);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // Protocol ID
        if (spdm_response->header.pci_doe_vendor_header.pci_protocol.protocol_id != PCI_PROTOCOL_ID_IDE_KM) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response protocol_id - 0x%02x", spdm_response->header.pci_doe_vendor_header.pci_protocol.protocol_id);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // CXL-IDE-KM Query Response
        if (spdm_response->pci_ide_km_query_resp.header.object_id != PCI_IDE_KM_OBJECT_ID_QUERY_RESP) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response object_id - 0x%02x", spdm_response->pci_ide_km_query_resp.header.object_id);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // IDE register
        uint32_t ide_reg_count = (uint32_t)(spdm_response_size - sizeof(*spdm_response)) / sizeof(uint32_t);
        if (spdm_response_size != sizeof(*spdm_response) + ide_reg_count * sizeof(uint32_t)) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response ide_reg_count - 0x%02x", ide_reg_count);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        is_valid_response = true;
    } while (false);

    return is_valid_response;
}

uint8_t make_pci_key_substream(pci_substream_t substream, pci_stream_direction_t direction)
{
    return (substream << 4) | (direction << 1);
}

const char* get_pci_substream_name(pci_substream_t substream)
{
    switch (substream) {
    case PCI_SUBSTREAM_POSTED:
        return "POSTED";
    case PCI_SUBSTREAM_NONPOSTED:
        return "NONPOSTED";
    case PCI_SUBSTREAM_COMPLETION:
        return "COMPLETION";
    default:
        return "UNKNOWN";
    }
    return "UNKNOWN";
}

const char* get_pci_stream_direction_name(pci_stream_direction_t direction)
{
    switch (direction) {
    case PCI_STREAM_DIRECTION_RX:
        return "RX";
    case PCI_STREAM_DIRECTION_TX:
        return "TX";
    default:
        return "UNKNOWN";
    }
    return "UNKNOWN";
}

bool spdm_test_case_vendor_defined_rsp_pci_ide_km_key_prog_success (void *test_context,
                                                                    pci_substream_t substream,
                                                                    pci_stream_direction_t direction)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    pci_ide_km_key_prog_test_request_t spdm_request;
    pci_ide_km_key_prog_test_response_t *spdm_response;
    uint8_t message[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t spdm_response_size;
    common_test_result_t test_result = COMMON_TEST_RESULT_PASS;
    spdm_vendor_defined_rsp_test_buffer_t *test_buffer;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(spdm_test_context->test_scratch_buffer_size ==
                   sizeof(spdm_vendor_defined_rsp_test_buffer_t));

    // Construct a CXL-IDE-KM Key Prog request
    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_header.spdm_version = test_buffer->version;
    spdm_request.header.spdm_header.request_response_code = SPDM_VENDOR_DEFINED_REQUEST;
    spdm_request.header.spdm_header.param1 = 0;
    spdm_request.header.spdm_header.param2 = 0;
    spdm_request.header.pci_doe_vendor_header.standard_id = SPDM_STANDARD_ID_PCISIG;
    spdm_request.header.pci_doe_vendor_header.len = sizeof(spdm_request.header.pci_doe_vendor_header.vendor_id);
    spdm_request.header.pci_doe_vendor_header.vendor_id = SPDM_VENDOR_ID_PCISIG;
    spdm_request.header.pci_doe_vendor_header.payload_length =
        sizeof(spdm_request.header.pci_doe_vendor_header.pci_protocol) +
        sizeof(spdm_request.pci_ide_km_key_prog) +
        sizeof(spdm_request.iv) +
        sizeof(spdm_request.key);
    spdm_request.header.pci_doe_vendor_header.pci_protocol.protocol_id = PCI_PROTOCOL_ID_IDE_KM;
    spdm_request.pci_ide_km_key_prog.header.object_id = PCI_IDE_KM_OBJECT_ID_KEY_PROG;
    spdm_request.pci_ide_km_key_prog.port_index = 0;
    spdm_request.pci_ide_km_key_prog.stream_id = 0;
    spdm_request.pci_ide_km_key_prog.port_index = 0;
    spdm_request.pci_ide_km_key_prog.key_sub_stream = make_pci_key_substream(substream, direction);
    spdm_request.iv[0] = 0;
    spdm_request.iv[1] = 1;
    libspdm_get_random_number(sizeof(spdm_request.key), (void *)spdm_request.key);

    xcena_test_record_test_message_custom("\n### pci_ide_km_key_prog for %s & %s\n",
                                           get_pci_substream_name(substream),
                                           get_pci_stream_direction_name(direction));
    print_payload((const char *)&spdm_request, sizeof(spdm_request), PAYLOAD_TYPE_REQUEST);

    // Run the PCI-IDE-KM Key Prog request
    spdm_response = (void *)message;
    spdm_response_size = sizeof(message);
    libspdm_zero_mem(message, sizeof(message));
    status = libspdm_send_receive_data(spdm_context, &test_buffer->session_id, false,
                                       &spdm_request, sizeof(spdm_request),
                                       spdm_response, &spdm_response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        xcena_test_record_test_assertion_custom_print(
            COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
        return false;
    }

    // Verify the response
    print_payload((const char *)spdm_response, spdm_response_size, PAYLOAD_TYPE_RESPONSE);

    test_result = COMMON_TEST_RESULT_PASS;
    bool is_valid_response = false;

    do
    {
        // minimum response size
        if (spdm_response_size < sizeof(*spdm_response)) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response size - %d", spdm_response_size);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // SPDM version
        if (spdm_response->header.spdm_header.spdm_version != test_buffer->version) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response version - 0x%02x", spdm_response->header.spdm_header.spdm_version);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // SPDM request response code
        if (spdm_response->header.spdm_header.request_response_code != SPDM_VENDOR_DEFINED_RESPONSE) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response code - 0x%02x", spdm_response->header.spdm_header.request_response_code);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // SPDM param1 & param2
        if ((spdm_response->header.spdm_header.param1 != 0) ||
            (spdm_response->header.spdm_header.param2 != 0)) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response param1 - 0x%02x, param2 - 0x%02x",
            spdm_response->header.spdm_header.param1, spdm_response->header.spdm_header.param2);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // Standard ID
        if (spdm_response->header.pci_doe_vendor_header.standard_id != SPDM_STANDARD_ID_PCISIG) {
            test_result = COMMON_TEST_RESULT_PASS;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response standard_id - 0x%02x", spdm_response->header.pci_doe_vendor_header.standard_id);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // Vendor ID
        if (spdm_response->header.pci_doe_vendor_header.vendor_id != SPDM_VENDOR_ID_PCISIG) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response vendor_id - 0x%02x", spdm_response->header.pci_doe_vendor_header.vendor_id);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // Payload length
        if (spdm_response->header.pci_doe_vendor_header.payload_length <
            sizeof(spdm_response->header.pci_doe_vendor_header.pci_protocol) +
            sizeof(spdm_response->pci_ide_km_key_prog_ack)) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response payload_length - 0x%02x", spdm_response->header.pci_doe_vendor_header.payload_length);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // Protocol ID
        if (spdm_response->header.pci_doe_vendor_header.pci_protocol.protocol_id != PCI_PROTOCOL_ID_IDE_KM) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response protocol_id - 0x%02x", spdm_response->header.pci_doe_vendor_header.pci_protocol.protocol_id);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // CXL-IDE-KM Key Prog Response
        if (spdm_response->pci_ide_km_key_prog_ack.header.object_id != PCI_IDE_KM_OBJECT_ID_KP_ACK) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response object_id - 0x%02x", spdm_response->pci_ide_km_key_prog_ack.header.object_id);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        is_valid_response = true;
    } while (false);

    return is_valid_response;
}

bool spdm_test_case_vendor_defined_rsp_pci_ide_km_key_set_go_stop_success (void *test_context,
                                                                           pci_substream_t substream,
                                                                           pci_stream_direction_t direction,
                                                                           pci_ide_km_key_set_go_stop_t gostop)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    pci_ide_km_key_set_go_test_request_t spdm_request;
    pci_ide_km_key_set_go_stop_test_response_t *spdm_response;
    uint8_t message[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t spdm_response_size;
    common_test_result_t test_result = COMMON_TEST_RESULT_PASS;
    spdm_vendor_defined_rsp_test_buffer_t *test_buffer;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(spdm_test_context->test_scratch_buffer_size ==
                   sizeof(spdm_vendor_defined_rsp_test_buffer_t));

    // Construct a CXL-IDE-KM Key Set Go request
    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_header.spdm_version = test_buffer->version;
    spdm_request.header.spdm_header.request_response_code = SPDM_VENDOR_DEFINED_REQUEST;
    spdm_request.header.spdm_header.param1 = 0;
    spdm_request.header.spdm_header.param2 = 0;
    spdm_request.header.pci_doe_vendor_header.standard_id = SPDM_STANDARD_ID_PCISIG;
    spdm_request.header.pci_doe_vendor_header.len = sizeof(spdm_request.header.pci_doe_vendor_header.vendor_id);
    spdm_request.header.pci_doe_vendor_header.vendor_id = SPDM_VENDOR_ID_PCISIG;
    spdm_request.header.pci_doe_vendor_header.payload_length =
        sizeof(spdm_request.header.pci_doe_vendor_header.pci_protocol) +
        sizeof(spdm_request.pci_ide_km_key_set_go);
    spdm_request.header.pci_doe_vendor_header.pci_protocol.protocol_id = PCI_PROTOCOL_ID_IDE_KM;
    spdm_request.pci_ide_km_key_set_go.header.object_id = (gostop == PCI_IDE_KM_KEY_SET_GO) ?
                                                          PCI_IDE_KM_OBJECT_ID_K_SET_GO : PCI_IDE_KM_OBJECT_ID_K_SET_STOP;
    spdm_request.pci_ide_km_key_set_go.port_index = 0;
    spdm_request.pci_ide_km_key_set_go.stream_id = 0;
    spdm_request.pci_ide_km_key_set_go.key_sub_stream = make_pci_key_substream(substream, direction);

    xcena_test_record_test_message_custom("\n### pci_ide_km_key_set_%s for %s & %s\n",
                                           (gostop == PCI_IDE_KM_KEY_SET_GO) ? "go" : "stop",
                                           get_pci_substream_name(substream),
                                           get_pci_stream_direction_name(direction));
    print_payload((const char *)&spdm_request, sizeof(spdm_request), PAYLOAD_TYPE_REQUEST);

    // Run the PCI-IDE-KM Key Set Go/Stop request
    spdm_response = (void *)message;
    spdm_response_size = sizeof(message);
    libspdm_zero_mem(message, sizeof(message));
    status = libspdm_send_receive_data(spdm_context, &test_buffer->session_id, false,
                                       &spdm_request, sizeof(spdm_request),
                                       spdm_response, &spdm_response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        xcena_test_record_test_assertion_custom_print(
            COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
        return false;
    }

    // Verify the response
    print_payload((const char *)spdm_response, spdm_response_size, PAYLOAD_TYPE_RESPONSE);

    test_result = COMMON_TEST_RESULT_PASS;
    bool is_valid_response = false;

    do
    {
        // minimum response size
        if (spdm_response_size < sizeof(*spdm_response)) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response size - %d", spdm_response_size);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // SPDM version
        if (spdm_response->header.spdm_header.spdm_version != test_buffer->version) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response version - 0x%02x", spdm_response->header.spdm_header.spdm_version);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // SPDM request response code
        if (spdm_response->header.spdm_header.request_response_code != SPDM_VENDOR_DEFINED_RESPONSE) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response code - 0x%02x", spdm_response->header.spdm_header.request_response_code);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // SPDM param1 & param2
        if ((spdm_response->header.spdm_header.param1 != 0) ||
            (spdm_response->header.spdm_header.param2 != 0)) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response param1 - 0x%02x, param2 - 0x%02x",
            spdm_response->header.spdm_header.param1, spdm_response->header.spdm_header.param2);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // Standard ID
        if (spdm_response->header.pci_doe_vendor_header.standard_id != SPDM_STANDARD_ID_PCISIG) {
            test_result = COMMON_TEST_RESULT_PASS;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response standard_id - 0x%02x", spdm_response->header.pci_doe_vendor_header.standard_id);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // Vendor ID
        if (spdm_response->header.pci_doe_vendor_header.vendor_id != SPDM_VENDOR_ID_PCISIG) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response vendor_id - 0x%02x", spdm_response->header.pci_doe_vendor_header.vendor_id);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // Payload length
        if (spdm_response->header.pci_doe_vendor_header.payload_length <
            sizeof(spdm_response->header.pci_doe_vendor_header.pci_protocol) +
            sizeof(spdm_response->pci_ide_km_key_set_go_stop_ack)) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response payload_length - 0x%02x", spdm_response->header.pci_doe_vendor_header.payload_length);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // Protocol ID
        if (spdm_response->header.pci_doe_vendor_header.pci_protocol.protocol_id != PCI_PROTOCOL_ID_IDE_KM) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response protocol_id - 0x%02x", spdm_response->header.pci_doe_vendor_header.pci_protocol.protocol_id);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        // PCI-IDE-KM Key Set Go/Stop Response
        if (spdm_response->pci_ide_km_key_set_go_stop_ack.header.object_id != PCI_IDE_KM_OBJECT_ID_K_SET_GOSTOP_ACK) {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        xcena_test_record_test_assertion_custom_print(
            test_result, "response object_id - 0x%02x", spdm_response->pci_ide_km_key_set_go_stop_ack.header.object_id);
        if (test_result == COMMON_TEST_RESULT_FAIL) { break; }

        is_valid_response = true;
    } while (false);

    return is_valid_response;
}

void spdm_test_case_vendor_defined_rsp_pci_ide_km_success (void *test_context)
{
    xcena_test_record_test_assertion_custom_set(
        SPDM_RESPONDER_TEST_GROUP_VENDOR_DEFINED_RSP,
        SPDM_RESPONDER_TEST_CASE_VENDOR_DEFINED_RSP_PCI_IDE_KM_SUCCESS);

    if (false == spdm_test_case_vendor_defined_rsp_pci_ide_km_query_success(test_context)) {
        return;
    }
    
    if (false == spdm_test_case_vendor_defined_rsp_pci_ide_km_key_prog_success(test_context,
                                                                               PCI_SUBSTREAM_POSTED,
                                                                               PCI_STREAM_DIRECTION_TX)) {
        return;
    }

    if (false == spdm_test_case_vendor_defined_rsp_pci_ide_km_key_prog_success(test_context,
                                                                               PCI_SUBSTREAM_NONPOSTED,
                                                                               PCI_STREAM_DIRECTION_TX)) {
        return;
    }

    if (false == spdm_test_case_vendor_defined_rsp_pci_ide_km_key_prog_success(test_context,
                                                                               PCI_SUBSTREAM_COMPLETION,
                                                                               PCI_STREAM_DIRECTION_TX)) {
        return;
    }

    if (false == spdm_test_case_vendor_defined_rsp_pci_ide_km_key_prog_success(test_context,
                                                                               PCI_SUBSTREAM_POSTED,
                                                                               PCI_STREAM_DIRECTION_RX)) {
        return;
    }

    if (false == spdm_test_case_vendor_defined_rsp_pci_ide_km_key_prog_success(test_context,
                                                                               PCI_SUBSTREAM_NONPOSTED,
                                                                               PCI_STREAM_DIRECTION_RX)) {
        return;
    }

    if (false == spdm_test_case_vendor_defined_rsp_pci_ide_km_key_prog_success(test_context,
                                                                               PCI_SUBSTREAM_COMPLETION,
                                                                               PCI_STREAM_DIRECTION_RX)) {
        return;
    }

    if (false == spdm_test_case_vendor_defined_rsp_pci_ide_km_key_set_go_stop_success (test_context,
                                                                                       PCI_SUBSTREAM_POSTED,
                                                                                       PCI_STREAM_DIRECTION_RX,
                                                                                       PCI_IDE_KM_KEY_SET_GO)) {
        return;
    }

    if (false == spdm_test_case_vendor_defined_rsp_pci_ide_km_key_set_go_stop_success (test_context,
                                                                                       PCI_SUBSTREAM_NONPOSTED,
                                                                                       PCI_STREAM_DIRECTION_RX,
                                                                                       PCI_IDE_KM_KEY_SET_GO)) {
        return;
    }

    if (false == spdm_test_case_vendor_defined_rsp_pci_ide_km_key_set_go_stop_success (test_context,
                                                                                       PCI_SUBSTREAM_COMPLETION,
                                                                                       PCI_STREAM_DIRECTION_RX,
                                                                                       PCI_IDE_KM_KEY_SET_GO)) {
        return;
    }

    if (false == spdm_test_case_vendor_defined_rsp_pci_ide_km_key_set_go_stop_success (test_context,
                                                                                       PCI_SUBSTREAM_POSTED,
                                                                                       PCI_STREAM_DIRECTION_TX,
                                                                                       PCI_IDE_KM_KEY_SET_GO)) {
        return;
    }

    if (false == spdm_test_case_vendor_defined_rsp_pci_ide_km_key_set_go_stop_success (test_context,
                                                                                       PCI_SUBSTREAM_NONPOSTED,
                                                                                       PCI_STREAM_DIRECTION_TX,
                                                                                       PCI_IDE_KM_KEY_SET_GO)) {
        return;
    }

    if (false == spdm_test_case_vendor_defined_rsp_pci_ide_km_key_set_go_stop_success (test_context,
                                                                                       PCI_SUBSTREAM_COMPLETION,
                                                                                       PCI_STREAM_DIRECTION_TX,
                                                                                       PCI_IDE_KM_KEY_SET_GO)) {
        return;
    }

    if (false == spdm_test_case_vendor_defined_rsp_pci_ide_km_key_set_go_stop_success (test_context,
                                                                                       PCI_SUBSTREAM_POSTED,
                                                                                       PCI_STREAM_DIRECTION_RX,
                                                                                       PCI_IDE_KM_KEY_SET_STOP)) {
        return;
    }

    if (false == spdm_test_case_vendor_defined_rsp_pci_ide_km_key_set_go_stop_success (test_context,
                                                                                       PCI_SUBSTREAM_NONPOSTED,
                                                                                       PCI_STREAM_DIRECTION_RX,
                                                                                       PCI_IDE_KM_KEY_SET_STOP)) {
        return;
    }

    if (false == spdm_test_case_vendor_defined_rsp_pci_ide_km_key_set_go_stop_success (test_context,
                                                                                       PCI_SUBSTREAM_COMPLETION,
                                                                                       PCI_STREAM_DIRECTION_RX,
                                                                                       PCI_IDE_KM_KEY_SET_STOP)) {
        return;
    }

    if (false == spdm_test_case_vendor_defined_rsp_pci_ide_km_key_set_go_stop_success (test_context,
                                                                                       PCI_SUBSTREAM_POSTED,
                                                                                       PCI_STREAM_DIRECTION_TX,
                                                                                       PCI_IDE_KM_KEY_SET_STOP)) {
        return;
    }

    if (false == spdm_test_case_vendor_defined_rsp_pci_ide_km_key_set_go_stop_success (test_context,
                                                                                       PCI_SUBSTREAM_NONPOSTED,
                                                                                       PCI_STREAM_DIRECTION_TX,
                                                                                       PCI_IDE_KM_KEY_SET_STOP)) {
        return;
    }

    if (false == spdm_test_case_vendor_defined_rsp_pci_ide_km_key_set_go_stop_success (test_context,
                                                                                       PCI_SUBSTREAM_COMPLETION,
                                                                                       PCI_STREAM_DIRECTION_TX,
                                                                                       PCI_IDE_KM_KEY_SET_STOP)) {
        return;
    }
}

void spdm_test_case_vendor_defined_rsp_pci_tdisp_success (void *test_context)
{
    xcena_test_record_test_assertion_custom_set(
        SPDM_RESPONDER_TEST_GROUP_VENDOR_DEFINED_RSP,
        SPDM_RESPONDER_TEST_CASE_VENDOR_DEFINED_RSP_PCI_TDISP_SUCCESS);
}

common_test_case_t m_spdm_test_group_vendor_defined_rsp[] = {
    {SPDM_RESPONDER_TEST_CASE_VENDOR_DEFINED_RSP_CXL_IDE_KM_SUCCESS,
     "spdm_test_case_vendor_defined_rsp_cxl_ide_km_success",
     spdm_test_case_vendor_defined_rsp_cxl_ide_km_success,
     spdm_test_case_vendor_defined_rsp_setup_version_any,
     spdm_test_case_common_teardown},
     {SPDM_RESPONDER_TEST_CASE_VENDOR_DEFINED_RSP_CXL_TSP_SUCCESS,
     "spdm_test_case_vendor_defined_rsp_cxl_tsp_success",
     spdm_test_case_vendor_defined_rsp_cxl_tsp_success,
     spdm_test_case_vendor_defined_rsp_setup_version_any,
     spdm_test_case_common_teardown},
    {SPDM_RESPONDER_TEST_CASE_VENDOR_DEFINED_RSP_PCI_IDE_KM_SUCCESS,
     "spdm_test_case_vendor_defined_rsp_pci_ide_km_success",
     spdm_test_case_vendor_defined_rsp_pci_ide_km_success,
     spdm_test_case_vendor_defined_rsp_setup_version_any,
     spdm_test_case_common_teardown},
    {SPDM_RESPONDER_TEST_CASE_VENDOR_DEFINED_RSP_PCI_TDISP_SUCCESS,
     "spdm_test_case_vendor_defined_rsp_pci_tdisp_success",
     spdm_test_case_vendor_defined_rsp_pci_tdisp_success,
     spdm_test_case_vendor_defined_rsp_setup_version_any,
     spdm_test_case_common_teardown},
    {COMMON_TEST_ID_END, NULL, NULL},
};
