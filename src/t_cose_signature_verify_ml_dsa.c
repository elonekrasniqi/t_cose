// t_cose_signature_verify_ml_dsa.c

#include "C:/Users/ADMIN/t_cose/inc/t_cose/t_cose_signature_verify.h"
#include "C:/Users/ADMIN/t_cose/inc/t_cose/t_cose_signature_sign.h"
#include "C:/Users/ADMIN/t_cose/inc/t_cose/t_cose_standard_constants.h"
#include "qcbor/qcbor.h"
#include "qcbor/UsefulBuf.h"
#include "oqs/oqs.h"
#include <oqs/oqs.h>
#include <string.h>
#include "C:/Users/ADMIN/t_cose/test/ml_dsa_keys.h"

#define T_COSE_ALGORITHM_ML_DSA_44 (-9999)

enum t_cose_err_t
t_cose_signature_verify_mldsa_cb(struct t_cose_signature_verify *me,
                                 uint32_t option_flags,
                                 const struct t_cose_sign_inputs *sign_inputs,
                                 const struct t_cose_parameter *parameters,
                                 const struct q_useful_buf_c signature)
{
    (void)option_flags;
    (void)parameters;
    (void)me;

    const uint8_t *msg     = sign_inputs->payload.ptr;
    size_t msg_len         = sign_inputs->payload.len;
    const uint8_t *sig_ptr = signature.ptr;
    size_t sig_len         = signature.len;

    // use global variables from ml_dsa_keys.h
    extern const uint8_t public_key[];
    extern const size_t public_key_len;
    printf("Verifying: msg_len=%zu, sig_len=%zu, pub_key_len=%zu\n", msg_len, sig_len, public_key_len);


    if (!msg || !sig_ptr || !public_key)
        return T_COSE_ERR_SIG_VERIFY;

    OQS_SIG *oqs_sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if (!oqs_sig)
        return T_COSE_ERR_SIG_VERIFY;

    OQS_STATUS rc = OQS_SIG_verify(
        oqs_sig,
        msg, msg_len,
        sig_ptr, sig_len,
        public_key);

    OQS_SIG_free(oqs_sig);

    return (rc == OQS_SUCCESS) ? T_COSE_SUCCESS : T_COSE_ERR_SIG_VERIFY;
}