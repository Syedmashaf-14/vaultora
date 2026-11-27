# Design Decision Record (DDR)
## Project: Vaultora — Zero-Trust Secure Document Management System
**Course:** CS3002 Information Security — Semester Project  
**Institution:** National University of Computer & Emerging Sciences (FAST-NUCES)  
**Author:** Syed Muhammad Mashaf Zaidi (Roll No: 23F-0529)  

---

## Executive Summary & Studied Cryptographic Algorithms Alignment
This document formalizes the architectural, cryptographic, and access-control decisions underpinning the **Vaultora Secure Document Management System**. Built on a **Zero-Trust Hybrid-Encrypted Architecture**, the system specifically integrates and defends the **six core information security algorithms** studied in the curriculum:

1. **AES (Advanced Encryption Standard):** Selected for high-throughput, authenticated client-side symmetric document payload encryption (AES-256-GCM).
2. **DES (Data Encryption Standard):** Analyzed and rejected as a legacy predecessor due to its inadequate 56-bit key length and susceptibility to differential cryptanalysis and brute-force attacks.
3. **SHA-512 (Secure Hash Algorithm 512-bit):** Selected as the primary cryptographic hash standard for end-to-end file integrity verification, PBKDF2 local key derivation, and the tamper-evident block-to-block audit chain.
4. **Diffie-Hellman (DH):** Investigated and evaluated for dynamic forward-secret shared secret agreement between active endpoints.
5. **ElGamal Cryptosystem:** Evaluated as an alternative asymmetric cipher based on the Discrete Logarithm Problem (DLP); contrasted with RSA regarding ciphertext expansion and computational overhead.
6. **RSA (Rivest-Shamir-Adleman):** Selected for asymmetric identity keypairs and multi-recipient Document Encryption Key (DEK) envelope wrapping via RSA-OAEP 2048-bit.

---

```
                              SYSTEM SECURITY TOPOLOGY
  ┌─────────────────────────────────────────────────────────────────────────────┐
  │                        CLIENT LAYER (Browser / React)                       │
  │  • Web Crypto API (SubtleCrypto)                                            │
  │  • RSA-OAEP 2048 Keypair per user (Public Key -> DB, Private Key -> Local)  │
  │  • PBKDF2 (SHA-512, 600,000 iter) derives KEK from password -> Encrypts Key │
  │  • File Upload: Client generates 256-bit AES-GCM DEK + 12-byte IV           │
  │  • Payload Checksum: 512-bit SHA-512 digest computed before encryption      │
  │  • Envelope Wrapping: Encrypts DEK with Recipient's RSA-OAEP Public Key     │
  └──────────────────────────────────────┬──────────────────────────────────────┘
                                         │ HTTPS (TLS 1.3) + HttpOnly JWT Cookie
                                         ▼
  ┌─────────────────────────────────────────────────────────────────────────────┐
  │                    SERVER / API GATEWAY (Node.js Express)                   │
  │  • Auth Middleware: Verifies JWT Cookie & Argon2id Password Hashes          │
  │  • Policy Enforcement Point (PEP): System RBAC + Document DAC (ACL)         │
  │  • Audit Logger: Creates append-only, SHA-512 hash-chained ledgers          │
  └──────────────────────────┬───────────────────────────────────┬──────────────┘
                             │ Metadata & ACL Updates            │ Pure Ciphertext
                             ▼                                   ▼
        ┌─────────────────────────────────────────┐     ┌───────────────────────┐
        │       METADATA DB (MongoDB Atlas)       │     │ ENCRYPTED BLOB VAULT  │
        │ • Users: { salt, argon2Hash, pubKey }   │     │ • /vault/<uuid>.enc   │
        │ • Docs:  { uuid, iv, tag, sha512,       │     │ • High-entropy raw    │
        │           ownerId, wrappedDEKs[] }      │     │   ciphertext only     │
        │ • Audit: { prevHash, currHash (512-bit)│     │ • No cleartext headers│
        └─────────────────────────────────────────┘     └───────────────────────┘
```

---

## Decision Record 1: Document Storage and Protection

### 1. The Problem Being Addressed
In a document management system, stored documents represent high-value targets for both external adversaries and internal threats (rogue database administrators, backup inspection, or compromised microservices). The system must guarantee that:
- Stored files cannot be read even if the underlying physical storage volume or database is completely breached.
- Predictable filenames do not allow attackers to enumerate or traverse files (preventing Insecure Direct Object References).
- Metadata (filenames, user associations, access rights) is strictly isolated from raw encrypted payloads.

### 2. Alternatives Considered
1. **Alternative 1.1: Plaintext File Storage with OS File-System Permissions**
   - *Description:* Storing cleartext files in a server directory (e.g., `/var/uploads/`) relying solely on OS access controls (`chmod 600`).
   - *Deficiencies:* Remote code execution (RCE) on the server or backup exfiltration instantly exposes all documents in cleartext. Violates Zero-Trust principles.
2. **Alternative 1.2: Legacy Symmetric Block Ciphers (DES in CBC Mode)**
   - *Description:* Encrypting server-side files using DES (Data Encryption Standard).
   - *Deficiencies:* DES utilizes an obsolete 56-bit key space ($2^{56} \approx 7.2 \times 10^{16}$ keys), which can be broken via brute force in less than a day using modern hardware. DES operates on small 64-bit blocks, making it susceptible to birthday attacks and differential cryptanalysis.
3. **Alternative 1.3: Database Binary Storage (MongoDB GridFS / BLOB Columns)**
   - *Description:* Storing unencrypted binary files directly inside database collections alongside metadata.
   - *Deficiencies:* Massive database memory footprint and index bloat. A database SQL/NoSQL injection exposes both raw files and operational metadata simultaneously.
4. **Alternative 1.4: Client-Side Envelope Encryption (AES-256-GCM) with Separated Physical Storage Volume (Selected)**
   - *Description:* Documents are encrypted in the client browser prior to transmission. Encrypted files are stored on an isolated volume strictly named with 128-bit random UUIDv4 (`/vault/<uuid>.enc`). All metadata, IVs, tags, SHA-512 hashes, and wrapped keys are stored in MongoDB Atlas.

### 3. Selected Approach and Justification
**Selected:** Alternative 1.4 — Client-Side Encryption with Separated Physical Vault Storage.
- **Justification:**
  - **Separation of Duties & Minimized Blast Radius:** The storage volume contains exclusively high-entropy binary ciphertext devoid of filenames, file extensions, or user identities. Compromising the storage drive yields only unintelligible random noise. Conversely, compromising the metadata database reveals access vectors and encrypted key wrappers, but zero payload content.
  - **IDOR Immunity via UUIDv4:** Filenames are mapped strictly to 128-bit version 4 UUIDs (e.g., `550e8400-e29b-41d4-a716-446655440000`). With $2^{122}$ possible values, brute-force guessing or path traversal attacks are mathematically infeasible.

### 4. Relevant Information Security Concepts
- **Principle of Least Privilege (PoLP):** Storage processes and database operators have zero privilege to read document contents.
- **Defense in Depth:** Dual-layer protection comprising physical volume isolation and end-to-end cryptographic encapsulation.
- **Zero-Trust Architecture (NIST SP 800-207):** The application server and database are treated as untrusted blind communication brokers.
- **Information Entropy:** Stored ciphertext exhibits near-maximum Shannon entropy ($H \approx 7.99$ bits/byte), preventing structural cryptanalysis.

### 5. Limitations, Risks, and Trade-offs
- **Limitation:** Inability to perform native server-side full-text search or document indexing without exposing cleartext.
- **Trade-off:** Additional client-side CPU utilization for bulk encryption of large files (mitigated through hardware-accelerated AES-NI).
- **Risk:** Loss of user authentication credentials and local key backup permanently renders the files unrecoverable.

---

## Decision Record 2: Cryptographic Approach and Key Management

### 2.1 The Problem Being Addressed
How to protect confidential document payloads against unauthorized disclosure, bit-flipping, and ciphertext manipulation while providing multi-user access without re-encrypting multi-megabyte payloads for every recipient. Furthermore, private keys must be secured on client devices without being exposed in cleartext to the browser host environment.

### 2.2 Alternatives Considered
1. **Alternative 2.1: Legacy DES / 3DES Encryption**
   - *Description:* Utilizing DES (56-bit) or Triple-DES (112/168-bit) symmetric encryption.
   - *Deficiencies:* DES is cryptographically broken due to its small key size. 3DES is computationally slow, vulnerable to Sweet32 collision attacks on 64-bit blocks, and deprecated by NIST.
2. **Alternative 2.2: Pure Asymmetric Encryption (RSA-2048 or ElGamal Direct File Encryption)**
   - *Description:* Encrypting file payloads directly using the recipient's RSA or ElGamal public key.
   - *Deficiencies:* 
     - *RSA Constraints:* RSA-2048 with OAEP can encrypt a maximum of 126 to 214 bytes of data directly. It cannot encrypt multi-megabyte files.
     - *ElGamal Constraints:* The ElGamal cryptosystem (based on the Discrete Logarithm Problem in a cyclic group $\mathbb{Z}_p^*$) produces a $2\times$ ciphertext expansion (output consists of pair $(c_1, c_2) = (g^k \bmod p, m \cdot y^k \bmod p)$), doubling storage and transmission requirements.
3. **Alternative 2.3: Diffie-Hellman Key Exchange (DH / ECDH) for Ephemeral Session Keys**
   - *Description:* Utilizing Diffie-Hellman key exchange between the document owner and each viewer to establish a shared symmetric session key.
   - *Deficiencies:* Diffie-Hellman requires both parties (or active session handshakes) to participate in key agreement. It does not provide asynchronous document sharing when recipients are offline.
4. **Alternative 2.4: Hybrid Envelope Encryption (AES-256-GCM + RSA-OAEP-2048 + SHA-512 Checksum) with Password-Derived KEK (Selected)**
   - *Description:* Each document is encrypted once using a unique, ephemeral 256-bit symmetric Document Encryption Key (DEK) via AES-GCM (Authenticated Encryption with Associated Data). The DEK is then wrapped (encrypted) individually for authorized users using their respective RSA-OAEP 2048-bit public keys. User private keys are protected on the client using a Key Encryption Key (KEK) derived from the user's password via PBKDF2 (SHA-512, 600,000 iterations). Document integrity is verified via a pre-encryption SHA-512 digest.

### 2.3 Selected Approach and Justification
**Selected:** Alternative 2.4 — Hybrid Envelope Encryption via Web Crypto API.
- **Justification:**
  - **AES vs. DES:** AES-256 provides a $2^{256}$ keyspace (infeasible to brute-force) compared to DES's broken 56-bit keyspace.
  - **Authenticated Encryption (AEAD):** AES-256-GCM provides both confidentiality and built-in authenticity via a 128-bit authentication tag. Any unauthorized modification (such as flipping a single bit in the ciphertext) immediately triggers an authentication failure (`OperationError`) in the Web Crypto API, halting decryption before corrupted plaintext can reach the application.
  - **RSA-OAEP Key Wrapping vs. ElGamal / Diffie-Hellman:** RSA key transport allows asynchronous wrapping: an owner can share a file with an offline user simply by querying their stored public key from MongoDB. Unlike ElGamal, RSA-wrapped DEKs occupy a compact 256-byte payload without doubling file size.
  - **SHA-512 Digest:** Generates a 512-bit cryptographic hash of the plaintext before encryption, verified on decryption to detect any potential transmission corruption.

### 2.4 Relevant Information Security Concepts
- **Kerckhoffs's Principle:** Security relies solely on the secrecy of the keys, not the obscurity of the algorithm.
- **AEAD (Authenticated Encryption with Associated Data):** Prevents ciphertext tampering, cut-and-paste attacks, and chosen-ciphertext attacks.
- **Key Hierarchy (KEK vs. DEK):** Decouples long-term identity keys from short-term data encryption keys.
- **Hardware Acceleration:** AES-GCM leverages modern CPU instructions (AES-NI and CLMUL) for multi-gigabit per second throughput.

### 2.5 Limitations, Risks, and Trade-offs
- **Limitation:** Inability for system administrators to recover lost files if a user forgets their password and misplaces their local private key backup.
- **Trade-off:** High iteration count for PBKDF2 with SHA-512 (600,000 rounds) creates an intentional computational delay during login to deter offline brute-force cracking.
- **Risk:** Cross-Site Scripting (XSS) in the browser application could potentially intercept decrypted keys residing temporarily in volatile memory.

---

## Decision Record 3: Authentication and Access-Control Model

### 3.1 The Problem Being Addressed
How to verify user identities, protect against credential stuffing, prevent session hijacking, and enforce fine-grained permissions across system administration, document ownership, and collaborative read/write operations without suffering from Insecure Direct Object References (IDOR).

### 3.2 Alternatives Considered
1. **Alternative 3.1: Pure Role-Based Access Control (RBAC)**
   - *Description:* Users are assigned static roles (`Admin`, `User`, `Auditor`). Permissions to view or delete documents are determined solely by whether the user possesses the `User` role.
   - *Deficiencies:* RBAC lacks resource-level granularity. Any user with the `User` role could request and view any document belonging to another user simply by guessing or tampering with document IDs (classic IDOR vulnerability).
2. **Alternative 3.2: Pure Attribute-Based Access Control (ABAC)**
   - *Description:* Access policies evaluated dynamically using complex boolean logic over environment, resource, and subject attributes.
   - *Deficiencies:* High computational complexity and governance overhead; difficult to audit deterministically and prone to policy misconfiguration.
3. **Alternative 3.3: Hybrid RBAC + Discretionary Access Control (DAC) via Document ACLs with Argon2id Authentication (Selected)**
   - *Description:* User authentication is enforced using memory-hard Argon2id password hashing and short-lived JWT tokens delivered via `HttpOnly`, `Secure`, `SameSite=Strict` cookies. Authorization utilizes a dual-layer Policy Enforcement Point (PEP):
     - **RBAC Layer:** Governs system-level administrative and auditing capabilities.
     - **DAC Layer:** Evaluates per-document Access Control Lists (ACLs) containing user identifiers, permission levels (`owner`, `editor`, `viewer`), temporal expiration timestamps (`expiresAt`), and their corresponding wrapped DEK.

### 3.3 Selected Approach and Justification
**Selected:** Alternative 3.3 — Hybrid RBAC + DAC with Argon2id and Strict Cookie Sessions.
- **Justification:**
  - **Argon2id Memory Hardness:** Standard password hashes can be calculated billions of times per second on commodity GPUs. Argon2id requires 64 MB of RAM and multi-threaded computation per hash, rendering parallel GPU and ASIC dictionary attacks mathematically impractical.
  - **Elimination of IDOR:** Every request to `/api/documents/:id/*` is intercepted by the Policy Enforcement Point (PEP). The PEP checks whether `req.user.id === doc.ownerId` OR whether `doc.wrappedDEKs` contains an unexpired entry for `req.user.id`. Changing the document ID in the URL parameter fails immediately with HTTP 403 Forbidden.
  - **Cookie Security:** Delivering JWTs in `HttpOnly` cookies ensures client-side JavaScript (`document.cookie`) cannot read or exfiltrate the token, neutralizing XSS credential theft. `SameSite=Strict` mitigates Cross-Site Request Forgery (CSRF).

### 3.4 Relevant Information Security Concepts
- **Dual-Layer Authorization:** Defense in depth separating administrative capabilities from resource ownership.
- **Temporal Least Privilege:** Access permissions can carry automated expiration timestamps (`expiresAt`), mitigating forgotten privilege accumulation.
- **Complete Mediation:** Every access attempt is validated by the server-side PEP before resource dispatch; UI button hiding is never treated as a security boundary.

### 3.5 Limitations, Risks, and Trade-offs
- **Limitation:** Revoking a stateless JWT prior to its natural expiration requires maintaining an in-memory or database token revocation blacklist.
- **Trade-off:** Checking the document ACL in the database on every download request adds a lightweight database lookup query.

---

## Decision Record 4: Document Sharing and Permission Revocation

### 4.1 The Problem Being Addressed
How to securely share a document with specific authorized recipients without exposing cleartext to the server, and how to revoke access such that revoked users can neither download future updates nor decrypt previously downloaded offline copies.

### 4.2 Alternatives Considered
1. **Alternative 4.1: Public or Unlisted Signed URLs (e.g., S3 Pre-signed Links)**
   - *Description:* Generating temporary download URLs with access tokens embedded in the query string.
   - *Deficiencies:* Signed URLs can be leaked in browser histories, proxy logs, or forwarded via chat/email. They cannot be revoked selectively without invalidating the signing key.
2. **Alternative 4.2: Dynamic Diffie-Hellman Key Exchange per Session**
   - *Description:* Requiring the document owner to be online to complete a Diffie-Hellman key agreement with the recipient whenever access is requested.
   - *Deficiencies:* Impossible for asynchronous workflows where the recipient accesses documents while the owner is offline.
3. **Alternative 4.3: Asymmetric Key Wrapping (RSA-OAEP) with Dual-Mode Revocation (Selected)**
   - *Description:* To share a document, the owner's client fetches the recipient's RSA public key, decrypts the document's DEK in local volatile memory using the owner's private key, wraps the DEK with the recipient's public key, and sends the resulting 256-byte `wrappedDEK` to be appended to the document's ACL in MongoDB. Revocation provides two distinct tiers:
     - **Standard Server-Side Revocation:** The server removes the recipient's entry from the document's ACL, immediately blocking all future API download requests.
     - **Cryptographic Revocation (Enhanced):** The owner downloads the file, decrypts it locally, generates a brand new DEK and IV, re-encrypts the file, re-wraps the new DEK only for remaining authorized recipients, and overwrites the vault ciphertext and ACL.

### 4.3 Selected Approach and Justification
**Selected:** Alternative 4.3 — Asymmetric Key Wrapping with Dual-Mode Revocation.
- **Justification:**
  - **Decoupled Key Management:** The bulk file payload (`/vault/<uuid>.enc`) remains untouched when sharing; only a lightweight wrapped key entry is appended to the metadata database.
  - **Immediate Access Severance:** Standard revocation takes effect instantaneously. Any subsequent download attempt triggers an HTTP 403 Forbidden at the PEP.
  - **Protection Against Stored Ciphertext:** Cryptographic revocation addresses the fundamental risk of an adversary retaining an encrypted blob offline: re-encrypting the payload with a fresh DEK guarantees that old wrapped keys can never decrypt newer versions of the document.

### 4.4 Relevant Information Security Concepts
- **End-to-End Encryption (E2EE):** Intermediary communication brokers never possess the cryptographic keys needed to read the payload.
- **Forward Secrecy in Document Versioning:** New cryptographic epochs isolate previous access grants from future file modifications.
- **Cache-Control Hardening:** Responses enforce `Cache-Control: no-store, no-cache, must-revalidate` to prevent local browser caching of decrypted payloads.

### 4.5 Limitations, Risks, and Trade-offs
- **Limitation:** The "Analog Hole" (Local Copy Limitation) — once an authorized recipient has legitimately decrypted and viewed a document on their screen, the server cannot prevent screen captures, local exports, or external photographing.
- **Trade-off:** Enhanced cryptographic revocation requires the document owner to download the cleartext and perform client-side re-encryption.

---

## Decision Record 5: Audit Logging and Protection of Audit Records

### 5.1 The Problem Being Addressed
Audit logs represent the primary mechanism for forensic investigations and breach detection. However, standard database audit tables are mutable: an attacker or malicious database administrator who obtains database access can modify log entries, alter timestamps, or delete records to conceal unauthorized exfiltration. The system must guarantee:
- Tamper-evidence: any modification, deletion, or insertion of audit records is mathematically detectable.
- Append-only immutability.
- Separation of duties: administrators can audit operations without gaining access to document plaintext.

### 5.2 Alternatives Considered
1. **Alternative 5.1: Flat File Server Logs (e.g., `access.log` / `audit.log`)**
   - *Description:* Writing security events to flat text files on the API host filesystem.
   - *Deficiencies:* Unstructured; difficult to query; vulnerable to local file manipulation or truncation by anyone with host shell access.
2. **Alternative 5.2: Standard Mutable Database Collection**
   - *Description:* Inserting JSON log records into a database collection (`audit_logs`) without cryptographic integrity links.
   - *Deficiencies:* Administrators with database access can execute `db.audit_logs.updateOne({ ... })` or `deleteOne({ ... })` without leaving a cryptographic trace.
3. **Alternative 5.3: Cryptographic SHA-512 Hash-Chained Append-Only Ledger (Selected)**
   - *Description:* Every security event is formatted as an immutable block cryptographically bound to the previous block via a 512-bit SHA-512 hash pointer:
     $$\text{CurrHash} = \text{SHA512}(\text{PrevHash} \parallel \text{Timestamp} \parallel \text{ActorId} \parallel \text{Action} \parallel \text{TargetDocId} \parallel \text{Outcome})$$
     The ledger begins with a deterministic Genesis Block (`prevHash: 000...000` with 128 hex digits). An automated integrity verification routine recalculates the chain from index $0$ to $N$. If any historical record is altered, inserted, or deleted, the mathematical hash link breaks at that exact block index.

### 5.3 Selected Approach and Justification
**Selected:** Alternative 5.3 — Cryptographic SHA-512 Hash-Chained Append-Only Ledger.
- **Justification:**
  - **Mathematical Proof of Integrity:** SHA-512 produces a 512-bit digest offering 256 bits of collision resistance against quantum and classical collision searches. Any alteration of an existing record alters its SHA-512 digest, which immediately creates a mismatch with the `prevHash` of the subsequent block.
  - **Tamper-Evident History:** An investigator or administrator can verify thousands of log records in milliseconds by verifying the hash chain.
  - **Comprehensive Operational Visibility:** The system logs both successful actions and failure states (`USER_LOGIN`, `DOCUMENT_UPLOAD`, `DOCUMENT_DOWNLOAD`, `PERMISSION_REVOKED`, `UNAUTHORIZED_ACCESS_ATTEMPT`, `PRIVILEGE_MISUSE_BLOCKED`).

### 5.4 Relevant Information Security Concepts
- **Non-Repudiation:** Cryptographically chained records establish an undeniable timeline of user and system events.
- **Cryptographic Hash Pointers:** Forms a linear Merkle-style directed acyclic structure ensuring history cannot be rewritten silently.
- **Principle of Separation of Duties:** System administrators are empowered to monitor operational access and verify chain integrity without having the ability to decrypt user documents.

### 5.5 Limitations, Risks, and Trade-offs
- **Limitation:** Hash chains detect tampering retroactively upon verification, but cannot prevent an attacker with root administrative privileges from executing a `DROP COLLECTION` command unless paired with external Write-Once-Read-Many (WORM) storage or remote syslog forwarders.
- **Trade-off:** Append-only ledgers grow monotonically and require log rotation policies or periodic root anchoring (e.g., publishing periodic block hashes to an external timestamping service).

---

## Comparison Matrix: Curriculum Studied Algorithms in Vaultora

| Algorithm | Type | Course Classification | Role in Vaultora Architecture | Technical Justification |
| :--- | :--- | :--- | :--- | :--- |
| **AES** | Symmetric Cipher | Modern Block Cipher | **Payload Encryption (AES-256-GCM)** | Hardware-accelerated (AES-NI), AEAD integrity tag, 256-bit key space. |
| **DES** | Symmetric Cipher | Legacy Block Cipher | **Evaluated & Rejected in DDR** | Deprecated: 56-bit key broken by brute force; 64-bit block prone to collisions. |
| **SHA-512** | Hash Function | Cryptographic Hash | **Integrity & Hash-Chained Audit Ledger** | 512-bit output; verifies cleartext integrity and chains audit blocks cryptographically. |
| **Diffie-Hellman** | Key Agreement | Public-Key Protocol | **Evaluated in DDR & Key Engine** | Discrete Logarithm based; evaluated for synchronous ephemeral session keys. |
| **ElGamal** | Asymmetric Cipher | Public-Key Cryptosystem | **Evaluated & Contrasted in DDR** | Discrete Logarithm based; rejected for bulk key wrapping due to $2\times$ ciphertext expansion. |
| **RSA** | Asymmetric Cipher | Public-Key Cryptosystem | **Key Wrapping (RSA-OAEP-2048)** | Integer Factorization based; enables asynchronous multi-recipient DEK wrapping. |

---
*End of Design Decision Record (CS3002 — FAST-NUCES)*
