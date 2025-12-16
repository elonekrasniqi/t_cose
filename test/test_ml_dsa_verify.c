#include "C:/Users/ADMIN/t_cose/inc/t_cose/t_cose_sign1_verify.h"
#include "C:/Users/ADMIN/QCBOR/inc/qcbor/qcbor.h"
#include "C:/Users/ADMIN/t_cose/inc/t_cose/t_cose_key.h"
#include "C:/Users/ADMIN/QCBOR/inc/qcbor/qcbor_spiffy_decode.h"
#include <stdio.h>
#include "ml_dsa_keys.h"
#include "C:/Users/ADMIN/t_cose/src/t_cose_signature_verify_ml_dsa.c"


// Your custom verifier function
extern enum t_cose_err_t t_cose_signature_verify_mldsa_cb(
    struct t_cose_signature_verify *me,
    uint32_t option_flags,
    const struct t_cose_sign_inputs *sign_inputs,
    const struct t_cose_parameter *parameters,
    const struct q_useful_buf_c signature);


// Verifier struct
static struct t_cose_signature_verify ml_dsa_verifier = {
    .verify_cb         = t_cose_signature_verify_mldsa_cb,
    .rs.next           = NULL
};

int main(void) {
    struct t_cose_sign1_verify_ctx verify_ctx;
    struct t_cose_key verify_key;

    verify_key.key.buffer.ptr = public_key;
    verify_key.key.buffer.len = public_key_len;

    struct q_useful_buf_c signed_cose = {signed_cose_bytes, signed_cose_bytes_len};

    UsefulBuf_MAKE_STACK_UB(payload_buf, 1024);  // allocate a buffer for the payload
    struct q_useful_buf_c payload;

    t_cose_sign1_verify_init(&verify_ctx, 0);
    t_cose_sign1_set_verification_key(&verify_ctx, verify_key);

    // ✅ Register your ML-DSA verifier into the context
    verify_ctx.me2.verifiers = &ml_dsa_verifier;

    enum t_cose_err_t result = t_cose_sign1_verify(&verify_ctx, signed_cose, &payload, NULL);

    if (result == T_COSE_SUCCESS) {
        printf("Verification succeeded!\n");
        printf("Message: %.*s\n", (int)payload.len, (char *)payload.ptr);
    } else {
        printf("Verification failed with error: %d\n", result);
    }

    return 0;
}
