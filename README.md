# Analysis of JOSE/COSE Hybrid Public Key Encryption (HPKE)

## Overview

This repository contains an academic analysis of **Hybrid Public Key Encryption (HPKE)** and its integration into **JOSE (JSON Object Signing and Encryption)** and **COSE (CBOR Object Signing and Encryption)**.

In addition to the theoretical analysis, the project includes **experimental implementation work** demonstrating **post-quantum digital signatures (ML-DSA)** using the **t_cose** library.

The work combines standards analysis with practical cryptographic experimentation, focusing on security context binding, post-quantum readiness, and COSE message processing.

---

## Objectives

- Analyze HPKE as defined in **RFC 9180**
- Study HPKE usage in **JOSE** and **COSE**
- Examine **KDF context construction** and its security role
- Discuss mitigation of protocol attacks (e.g., Unknown Key Share)
- Explore post-quantum cryptography integration in COSE
- Implement and verify **ML-DSA** signing and verification in **t_cose**

---

## Implementation Summary

### t_cose Integration

- Based on the **dev branch** of the `t_cose` library
- Extended `t_cose` to support **ML-DSA**
- Integrated **liboqs (Open Quantum Safe)** as the PQC backend
- Implemented **COSE_Sign1** signing and verification

---

## Verified Functionality

- ✔ ML-DSA signing produces a valid **COSE_Sign1** structure  
- ✔ Payload is processed correctly  
- ✔ Signature buffer is correctly allocated (≈ 2.7–3 KB)  
- ✔ End-to-end verification succeeds  

### Example Verification Output

```text
Verifying: msg_len=13, sig_len=2420, pub_key_len=1312
Verification succeeded!
Message: Hello ML-DSA!

---

## Technologies Used

- **t_cose** – COSE signing and verification library
- **liboqs** – Open Quantum Safe post-quantum cryptography library
- **ML-DSA** – Post-quantum digital signature algorithm
- **COSE** – CBOR Object Signing and Encryption
- **JOSE** – JSON Object Signing and Encryption
- **OpenSSL** – Cryptographic backend (classical algorithms)


## References

- **RFC 9180** – Hybrid Public Key Encryption (HPKE)
- **Use of HPKE with COSE** – IETF Internet-Draft
- **Use of HPKE with JOSE** – IETF Internet-Draft
- **NIST SP 800-56A Rev. 3** – Key Establishment Recommendations
- **liboqs** – https://openquantumsafe.org

---

## Disclaimer

This project is intended for **research and educational purposes only**.  
The implementation is **experimental** and **not intended for production use**.