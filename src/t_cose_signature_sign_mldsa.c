#include "t_cose/t_cose_signature_sign.h"
#include "t_cose/t_cose_standard_constants.h"
#include "qcbor/qcbor.h"
#include "qcbor/UsefulBuf.h"
#include "oqs/oqs.h"
#include <string.h>
#include <stdio.h>

#define T_COSE_ALGORITHM_ML_DSA_44 (-9999)

enum t_cose_err_t t_cose_signature_sign(
    int32_t cose_algorithm_id,
    struct q_useful_buf_c protected_parameters,
    struct q_useful_buf_c payload,
    struct t_cose_key signing_key,
    struct q_useful_buf buffer_to_hold_result,
    struct q_useful_buf_c *result)
{
    printf("\n=== ML-DSA Signing backend triggered ===\n");

    printf("[DEBUG] Algorithm ID: %d\n", cose_algorithm_id);
    if (cose_algorithm_id != T_COSE_ALGORITHM_ML_DSA_44) {
        printf("[ERROR] Unsupported algorithm: %d\n", cose_algorithm_id);
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }

    const uint8_t *private_key = (const uint8_t *)signing_key.key.buffer.ptr;
    size_t private_key_len = signing_key.key.buffer.len;

    printf("[DEBUG] Private key length: %zu (expected %d)\n", private_key_len, OQS_SIG_dilithium_2_length_secret_key);
    if (private_key_len != OQS_SIG_dilithium_2_length_secret_key) {
        printf("[ERROR] Invalid private key length\n");
        return T_COSE_ERR_FAIL;
    }

    printf("[DEBUG] Payload length: %zu\n", payload.len);
    printf("[DEBUG] Protected header length: %zu\n", protected_parameters.len);

    uint8_t temp_msg[1024];
    if (protected_parameters.len + payload.len > sizeof(temp_msg)) {
        printf("[ERROR] Combined message too large (%zu bytes)\n", protected_parameters.len + payload.len);
        return T_COSE_ERR_TOO_SMALL;
    }

    memcpy(temp_msg, protected_parameters.ptr, protected_parameters.len);
    memcpy(temp_msg + protected_parameters.len, payload.ptr, payload.len);
    size_t msg_len = protected_parameters.len + payload.len;

    printf("[DEBUG] Total message to sign length: %zu\n", msg_len);

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if (!sig) {
        printf("[ERROR] OQS_SIG_new failed\n");
        return T_COSE_ERR_FAIL;
    }

    size_t sig_len = 0;
    OQS_STATUS rc = OQS_SIG_sign(sig,
                                  (uint8_t *)buffer_to_hold_result.ptr,
                                  &sig_len,
                                  temp_msg,
                                  msg_len,
                                  private_key);

    printf("[DEBUG] OQS_SIG_sign returned: %d\n", rc);
    OQS_SIG_free(sig);

    if (rc != OQS_SUCCESS) {
        printf("[ERROR] OQS_SIG_sign failed\n");
        return T_COSE_ERR_FAIL;
    }

    result->ptr = buffer_to_hold_result.ptr;
    result->len = sig_len;

    printf("[SUCCESS] Signature created! Length: %zu bytes\n", sig_len);
    return T_COSE_SUCCESS;
}
