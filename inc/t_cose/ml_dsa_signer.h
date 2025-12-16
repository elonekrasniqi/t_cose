#ifndef ML_DSA_SIGNER_H
#define ML_DSA_SIGNER_H

#include "t_cose/t_cose_common.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose/t_cose_key.h"

enum t_cose_err_t ml_dsa_signer(struct t_cose_key signing_key,
                                int32_t cose_alg_id,
                                struct q_useful_buf_c protected_parameters,
                                struct q_useful_buf_c payload,
                                struct q_useful_buf buffer_for_output,
                                struct q_useful_buf_c *result);

#endif /* ML_DSA_SIGNER_H */
