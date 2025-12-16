#include "C:/Users/ADMIN/t_cose/inc/t_cose/ml_dsa_signer.h"
#include "C:/Users/ADMIN/t_cose/inc/t_cose/t_cose_standard_constants.h"
#include "C:/Users/ADMIN/t_cose/inc/t_cose/t_cose_signature_sign.h"
#include "C:/Users/ADMIN/t_cose/liboqs/build/include/oqs/oqs.h"
#include "C:/Users/ADMIN/t_cose/inc/t_cose/t_cose_common.h"
#include <string.h>
#include <stdio.h> 


enum t_cose_err_t ml_dsa_signer(struct t_cose_key signing_key,
                                int32_t cose_alg_id,
                                struct q_useful_buf_c protected_parameters,
                                struct q_useful_buf_c payload,
                                struct q_useful_buf buffer_for_output,
                                struct q_useful_buf_c *result)
{
    printf("SIGNING key pointer: %p\n", signing_key.key.buffer.ptr);
    printf("Payload length: %zu\n", payload.len);
    printf("Output buffer size: %zu\n", buffer_for_output.len);

    if (cose_alg_id != -9999) {  // Match your custom ML-DSA algorithm ID
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }

    size_t sig_len = buffer_for_output.len;

    // Initialize Dilithium2 signer
    OQS_SIG *oqs_sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if (!oqs_sig) {
        return T_COSE_ERR_SIG_FAIL;
    }

    // ✅ CHECK: Is buffer big enough?
    if (buffer_for_output.len < oqs_sig->length_signature) {
        printf("❌ Buffer too small! Provided: %zu, Required: %zu\n",
               buffer_for_output.len, oqs_sig->length_signature);
        OQS_SIG_free(oqs_sig);
        return T_COSE_ERR_SIG_FAIL;
    }

    // Sign using the payload (no hashing)
    int ret = OQS_SIG_sign(oqs_sig,
                           buffer_for_output.ptr,
                           &sig_len,
                           payload.ptr,
                           payload.len,
                           signing_key.key.buffer.ptr);

    OQS_SIG_free(oqs_sig);

    if (ret != OQS_SUCCESS) {
        return T_COSE_ERR_SIG_FAIL;
    }

    *result = (struct q_useful_buf_c){
        .ptr = buffer_for_output.ptr,
        .len = sig_len
    };

    return T_COSE_SUCCESS;
}
