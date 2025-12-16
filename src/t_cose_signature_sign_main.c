/*
 * Modified t_cose_signature_sign_main.c to add support for ML-DSA (Dilithium2) via liboqs
 */

#include "qcbor/qcbor_encode.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose/t_cose_signature_main.h"
#include "t_cose/t_cose_signature_sign_main.h"
#include "t_cose/t_cose_signature_sign.h"
#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_parameters.h"
#include "C:/Users/ADMIN/t_cose/inc/t_cose/ml_dsa_signer.h"
#include "t_cose_util.h"
#include "t_cose_crypto.h"
#include "C:/Users/ADMIN/t_cose/liboqs/install/include/oqs/oqs.h"
#include <string.h>

#define T_COSE_ALGORITHM_ML_DSA_44 (-9999)  // Match your custom algo ID

/** This is an implementation of \ref t_cose_signature_sign_headers_cb */
static void
t_cose_signature_sign_headers_main_cb(struct t_cose_signature_sign *me_x,
                                      struct t_cose_parameter **params)
{
    struct t_cose_signature_sign_main *me =
        (struct t_cose_signature_sign_main *)me_x;

    me->local_params[0] = t_cose_param_make_alg_id(me->cose_algorithm_id);
    if (!q_useful_buf_c_is_null(me->kid)) {
        me->local_params[1] = t_cose_param_make_kid(me->kid);
        me->local_params[0].next = &me->local_params[1];
    }

    *params = me->local_params;
}

/** Custom signer for ML-DSA using liboqs */
static enum t_cose_err_t
t_cose_signature_sign_custom_ml_dsa(int32_t cose_algorithm_id,
                                    struct q_useful_buf_c payload,
                                    struct t_cose_key signing_key,
                                    struct q_useful_buf buffer_for_signature,
                                    struct q_useful_buf_c *signature_out)
{
    return ml_dsa_signer(signing_key,
                         cose_algorithm_id,
                         NULL_Q_USEFUL_BUF_C,  // protected_parameters is not used in your impl
                         payload,
                         buffer_for_signature,
                         signature_out);
}

/** This is an implementation of \ref t_cose_signature_sign_cb */
static enum t_cose_err_t
t_cose_signature_sign1_main_cb(struct t_cose_signature_sign *me_x,
                               const struct t_cose_sign_inputs *sign_inputs,
                               QCBOREncodeContext *cbor_encoder)
{
    struct t_cose_signature_sign_main *me = (struct t_cose_signature_sign_main *)me_x;
    enum t_cose_err_t return_value;
    Q_USEFUL_BUF_MAKE_STACK_UB(buffer_for_tbs_hash, T_COSE_MAIN_MAX_HASH_SIZE);
    struct q_useful_buf buffer_for_signature;
    struct q_useful_buf_c tbs_hash;
    struct q_useful_buf_c signature;

    return_value = qcbor_encode_error_to_t_cose_error(cbor_encoder);
    if (return_value != T_COSE_SUCCESS)
        return return_value;

    QCBOREncode_OpenBytes(cbor_encoder, &buffer_for_signature);

    if (me->cose_algorithm_id == T_COSE_ALGORITHM_ML_DSA_44) {
        if (QCBOREncode_IsBufferNULL(cbor_encoder)) {
            // Predict signature length (Dilithium2 = ~2420 bytes)
            signature.ptr = NULL;
            signature.len = 2420;
            return T_COSE_SUCCESS;
        } else {
            return_value = t_cose_signature_sign_custom_ml_dsa(
                me->cose_algorithm_id,
                sign_inputs->payload,
                me->signing_key,
                buffer_for_signature,
                &signature);

            if (return_value != T_COSE_SUCCESS)
                return return_value;

            QCBOREncode_CloseBytes(cbor_encoder, signature.len);
            return T_COSE_SUCCESS;
        }
    }

    // 👇 Only used for non-ML-DSA
    if (QCBOREncode_IsBufferNULL(cbor_encoder)) {
        signature.ptr = NULL;
        t_cose_crypto_sig_size(me->cose_algorithm_id, me->signing_key, &signature.len);
        return_value = T_COSE_SUCCESS;
    } else {
        return_value = create_tbs_hash(me->cose_algorithm_id,
                                       sign_inputs,
                                       buffer_for_tbs_hash,
                                       &tbs_hash);
        if (return_value != T_COSE_SUCCESS)
            return return_value;

        return_value = t_cose_crypto_sign(me->cose_algorithm_id,
                                          me->signing_key,
                                          me->crypto_context,
                                          tbs_hash,
                                          buffer_for_signature,
                                          &signature);
        if (return_value != T_COSE_SUCCESS)
            return return_value;

        QCBOREncode_CloseBytes(cbor_encoder, signature.len);
    }

    return T_COSE_SUCCESS;
}


/** This is an implementation of \ref t_cose_signature_sign1_cb */
static enum t_cose_err_t
t_cose_signature_sign_main_cb(struct t_cose_signature_sign *me_x,
                              struct t_cose_sign_inputs *sign_inputs,
                              QCBOREncodeContext *cbor_encoder)
{
#ifndef T_COSE_DISABLE_COSE_SIGN
    struct t_cose_signature_sign_main *me = (struct t_cose_signature_sign_main *)me_x;
    enum t_cose_err_t return_value;
    struct t_cose_parameter *parameters;

    QCBOREncode_OpenArray(cbor_encoder);

    t_cose_signature_sign_headers_main_cb(me_x, &parameters);
    t_cose_params_append(&parameters, me->added_signer_params);
    t_cose_headers_encode(cbor_encoder, parameters, &sign_inputs->sign_protected);

    return_value = t_cose_signature_sign1_main_cb(me_x, sign_inputs, cbor_encoder);

    QCBOREncode_CloseArray(cbor_encoder);

    return return_value;
#else
    (void)me_x;
    (void)sign_inputs;
    (void)cbor_encoder;
    return T_COSE_ERR_UNSUPPORTED;
#endif
}

void
t_cose_signature_sign_main_init(struct t_cose_signature_sign_main *me,
                                const int32_t cose_algorithm_id)
{
    memset(me, 0, sizeof(*me));
    me->s.rs.ident        = RS_IDENT(TYPE_RS_SIGNER, 'M');
    me->s.headers_cb      = t_cose_signature_sign_headers_main_cb;
    me->s.sign_cb         = t_cose_signature_sign_main_cb;
    me->s.sign1_cb        = t_cose_signature_sign1_main_cb;
    me->cose_algorithm_id = cose_algorithm_id;
}
