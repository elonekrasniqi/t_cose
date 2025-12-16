#include "C:/Users/ADMIN/t_cose/inc/t_cose/t_cose_parameters.h"
#include "C:/Users/ADMIN/t_cose/inc/t_cose/t_cose_common.h"
#include "C:/Users/ADMIN/t_cose/inc/t_cose/q_useful_buf.h"
#include "C:/Users/ADMIN/t_cose/inc/t_cose/ml_dsa_signer.h"
#include "C:/Users/ADMIN/t_cose/inc/t_cose/t_cose_standard_constants.h"

#include "C:/Users/ADMIN/t_cose/src/t_cose_crypto.h"
#include "C:/Users/ADMIN/t_cose/liboqs/install/include/oqs/oqs.h"
#include <string.h>

// Make sure this matches your t_cose_standard_constants.h
#define T_COSE_ALGORITHM_ML_DSA_44 (-9999)

// Forward declaration if fallback is OpenSSL
extern enum t_cose_err_t t_cose_crypto_sign_openssl(int32_t cose_algorithm_id,
                                                    struct t_cose_key signing_key,
                                                    void *crypto_context,
                                                    struct q_useful_buf_c hash_to_sign,
                                                    struct q_useful_buf signature_buffer,
                                                    struct q_useful_buf_c *signature);

enum t_cose_err_t t_cose_crypto_sign_mldsa(int32_t cose_algorithm_id,
                                           struct t_cose_key signing_key,
                                           void *crypto_context,
                                           struct q_useful_buf_c payload, // not hash
                                           struct q_useful_buf signature_buffer,
                                           struct q_useful_buf_c *signature)
{
    if (cose_algorithm_id == T_COSE_ALGORITHM_ML_DSA_44) {
        OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
        if (!sig) return T_COSE_ERR_SIG_FAIL;

        size_t sig_len = signature_buffer.len;

        int ret = OQS_SIG_sign(sig,
                               signature_buffer.ptr, &sig_len,
                               payload.ptr, payload.len,
                               signing_key.key.buffer.ptr);

        OQS_SIG_free(sig);

        if (ret != OQS_SUCCESS) return T_COSE_ERR_SIG_FAIL;

        signature->ptr = signature_buffer.ptr;
        signature->len = sig_len;

        return T_COSE_SUCCESS;
    }

    return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;  // Avoid fallback to OpenSSL
}
