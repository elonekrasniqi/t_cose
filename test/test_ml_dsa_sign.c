#include "C:/Users/ADMIN/t_cose/inc/t_cose/t_cose_sign1_sign.h"
#include "C:/Users/ADMIN/QCBOR/inc/qcbor/UsefulBuf.h"
#include "C:/Users/ADMIN/QCBOR/inc/qcbor/qcbor.h"
#include "C:/Users/ADMIN/t_cose/inc/t_cose/t_cose_standard_constants.h"
#include "C:/Users/ADMIN/t_cose/inc/t_cose/t_cose_signature_sign.h"
#include "C:/Users/ADMIN/t_cose/liboqs/build/include/oqs/oqs.h"
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

// Define ML-DSA algorithm ID (must match your implementation)
#define T_COSE_ALGORITHM_ML_DSA_44 (-9999)

void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
        if ((i + 1) % 32 == 0)
            printf("\n");
    }
    printf("\n");
}
void print_as_c_array(const char* name, const uint8_t* data, size_t len) {
    printf("uint8_t %s[] = {\n", name);
    for (size_t i = 0; i < len; i++) {
        printf("0x%02X%s", data[i], (i < len - 1) ? ", " : "");
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("};\nsize_t %s_len = sizeof(%s);\n\n", name, name);
}

// Custom backend implementation forward declaration
extern enum t_cose_err_t t_cose_signature_sign_custom(
    int32_t cose_algorithm_id,
    struct q_useful_buf_c protected_parameters,
    struct q_useful_buf_c payload,
    struct t_cose_key signing_key,
    struct q_useful_buf buffer_to_hold_result,
    struct q_useful_buf_c *result);


int main(void) {
    struct t_cose_sign1_sign_ctx sign_ctx;
    struct t_cose_key signing_key;
    struct q_useful_buf_c kid = NULL_Q_USEFUL_BUF_C;

    // Generate a Dilithium keypair using liboqs
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if (!sig) {
        printf("Failed to initialize OQS_SIG\n");
        return 1;
    }

    uint8_t public_key[OQS_SIG_dilithium_2_length_public_key];
    uint8_t private_key[OQS_SIG_dilithium_2_length_secret_key];
    if (OQS_SIG_keypair(sig, public_key, private_key) != OQS_SUCCESS) {
        printf("Keypair generation failed\n");
        OQS_SIG_free(sig);
        return 1;
    }

    signing_key.key.buffer.ptr = private_key;
    signing_key.key.buffer.len = sizeof(private_key);

    const char *msg = "Hello ML-DSA!";
    struct q_useful_buf_c payload = {msg, strlen(msg)};

    UsefulBuf_MAKE_STACK_UB(signature_buf, 3000);
    struct q_useful_buf_c signed_cose;

    t_cose_sign1_sign_init(&sign_ctx, 0, T_COSE_ALGORITHM_ML_DSA_44);
    t_cose_sign1_set_signing_key(&sign_ctx, signing_key, kid);

    enum t_cose_err_t result = t_cose_sign1_sign(&sign_ctx, payload, signature_buf, &signed_cose);

    if (result == T_COSE_SUCCESS) {
        printf("Signature succeeded! Signed COSE size: %zu bytes\n", signed_cose.len);
         printf("🔐 Signed COSE (Hex):\n");
         print_as_c_array("public_key", public_key, sizeof(public_key));
print_as_c_array("signed_cose_bytes", signed_cose.ptr, signed_cose.len);
    print_hex((const uint8_t *)signed_cose.ptr, signed_cose.len);
    } else {
        printf("Signature failed with error: %d\n", result);
    }

    OQS_SIG_free(sig);
    return 0;
}
