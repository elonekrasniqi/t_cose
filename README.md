# Analysis of JOSE/COSE Hybrid Public Key Encryption (HPKE)

## Overview

This repository presents an academic and experimental analysis of **Hybrid Public Key Encryption (HPKE)** and its integration within **JOSE (JSON Object Signing and Encryption)** and **COSE (CBOR Object Signing and Encryption)** ecosystems.

The work combines **standards-based cryptographic analysis** with **hands-on implementation**, focusing on secure context binding, protocol-level attack mitigation, and **post-quantum cryptography (PQC)** readiness. In addition to HPKE analysis, the project includes an **experimental implementation of post-quantum digital signatures (ML-DSA)** using an extended version of the **t_cose** library.

This repository is intended to bridge theoretical cryptographic standards with practical COSE message processing and verification.

---

## Project Objectives

The primary objectives of this project are:

- Analyze **Hybrid Public Key Encryption (HPKE)** as specified in **RFC 9180**
- Study and compare HPKE usage within **JOSE** and **COSE**
- Examine **KDF context construction** and its role in binding protocol state
- Discuss mitigation of protocol-level attacks, including **Unknown Key Share (UKS)** attacks
- Explore **post-quantum cryptography integration** in COSE
- Implement and experimentally verify **ML-DSA** signing and verification using **t_cose**

---

## Technical Scope

### Standards and Protocol Analysis

- Detailed review of HPKE modes and primitives defined in **RFC 9180**
- Analysis of HPKE encapsulation and context binding in JOSE and COSE
- Evaluation of security properties achieved through correct KDF context construction
- Discussion of attack surfaces and mitigation strategies in hybrid encryption schemes

### Post-Quantum Cryptography Exploration

- Integration of **ML-DSA**, a post-quantum digital signature algorithm
- Evaluation of COSE message compatibility with post-quantum signatures
- Experimental validation of message signing and verification workflows

---

## Implementation Summary

### t_cose Extension

The implementation work is based on the **development branch** of the `t_cose` library and includes the following enhancements:

- Extension of `t_cose` to support **ML-DSA**
- Integration of **liboqs (Open Quantum Safe)** as the post-quantum cryptographic backend
- Implementation of **COSE_Sign1** message creation and verification
- Proper handling of large post-quantum signature sizes

---

## Verified Functionality

The following functionality has been successfully implemented and verified:

- ✔ ML-DSA signing produces a valid **COSE_Sign1** structure  
- ✔ Payload data is processed and preserved correctly  
- ✔ Signature buffers are allocated correctly (approximately **2.7–3 KB**)  
- ✔ End-to-end signature verification completes successfully  

### Example Verification Output

```text
Verifying: msg_len=13, sig_len=2420, pub_key_len=1312
Verification succeeded!
Message: Hello ML-DSA!
```

## Technologies Used

- **t_cose** – COSE signing and verification library
- **liboqs** – Open Quantum Safe post-quantum cryptography library
- **ML-DSA** – Post-quantum digital signature algorithm
- **COSE** – CBOR Object Signing and Encryption
- **JOSE** – JSON Object Signing and Encryption
- **OpenSSL** – Cryptographic backend for classical algorithms

---

## References

- **RFC 9180** – Hybrid Public Key Encryption (HPKE)
- **Use of HPKE with COSE** – IETF Internet-Draft
- **Use of HPKE with JOSE** – IETF Internet-Draft
- **NIST SP 800-56A Rev. 3** – Recommendations for Key Establishment
- **liboqs** – https://openquantumsafe.org

---

## Disclaimer

This project is intended **solely for research and educational purposes**.

All implementations are **experimental** and **not suitable for production use**. Cryptographic algorithms, libraries, and integrations used in this project may be incomplete, unstable, or subject to change.
