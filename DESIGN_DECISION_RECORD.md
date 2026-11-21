# Design Decision Record (DDR)
## Project: Vaultora — Zero-Trust Secure Document Management System
**Course:** CS3002 Information Security — Semester Project  
**Institution:** National University of Computer & Emerging Sciences (FAST-NUCES)  
**Author:** Syed Muhammad Mashaf Zaidi (Roll No: 23F-0529)  

---

## Executive Summary
This document formalizes the architectural, cryptographic, and access-control decisions underpinning the **Vaultora Secure Document Management System**. Built on a **Zero-Trust Hybrid-Encrypted Architecture**, the system guarantees end-to-end payload confidentiality, mathematical non-repudiation, strict cryptographic separation of duties, and tamper-evident auditability. 

The decisions below address the five core mandatory areas prescribed by the CS3002 specification:
1. **Document Storage and Protection**
2. **Cryptographic Approach and Key Management**
3. **Authentication and Access-Control Model**
4. **Document Sharing and Permission Revocation**
5. **Audit Logging and Protection of Audit Records**

---

```
                                SYSTEM SECURITY TOPOLOGY
  ┌─────────────────────────────────────────────────────────────────────────────┐
  │                        CLIENT LAYER (Browser / React)                       │
  │  • Web Crypto API (SubtleCrypto)                                            │
  │  • RSA-OAEP 2048 Keypair per user (Public Key -> DB, Private Key -> Local)  │
  │  • PBKDF2 (SHA-256, 600,000 iter) derives KEK from password -> Encrypts Key │
  │  • File Upload: Client generates 256-bit AES-GCM DEK + 12-byte IV           │
  │  • Envelope Wrapping: Encrypts DEK with Recipient's RSA-OAEP Public Key     │
  └──────────────────────────────────────┬──────────────────────────────────────┘
                                         │ HTTPS (TLS 1.3) + HttpOnly JWT Cookie
                                         ▼
  ┌─────────────────────────────────────────────────────────────────────────────┐
  │                    SERVER / API GATEWAY (Node.js Express)                   │
  │  • Auth Middleware: Verifies JWT Cookie & Argon2id Password Hashes          │
  │  • Policy Enforcement Point (PEP): System RBAC + Document DAC (ACL)         │
  │  • Audit Logger: Creates append-only, SHA-256 hash-chained ledgers          │
  └──────────────────────────┬───────────────────────────────────┬──────────────┘
                             │ Metadata & ACL Updates            │ Pure Ciphertext
                             ▼                                   ▼
        ┌─────────────────────────────────────────┐     ┌───────────────────────┐
        │          METADATA DB (MongoDB)          │     │ ENCRYPTED BLOB VAULT  │
        │ • Users: { salt, argon2Hash, pubKey }   │     │ • /vault/<uuid>.enc   │
        │ • Docs:  { uuid, iv, tag, sha256,       │     │ • High-entropy raw    │
        │           ownerId, wrappedDEKs[] }      │     │   ciphertext only     │
        │ • Audit: { prevHash, currHash }         │     │ • No cleartext headers│
        └─────────────────────────────────────────┘     └───────────────────────┘
```

---

## Decision Record 1: Document Storage and Protection

### 1. The Problem Being Addressed
In a document management system, stored documents represent high-value targets for both external adversaries (e.g., unauthorized file system exfiltration) and internal threats (e.g., rogue database administrators, backup inspection, or compromised microservices). The system must guarantee that:
- Stored files cannot be read even if the underlying physical storage volume or database is completely breached.
- Predictable filenames do not allow attackers to enumerate or traverse files (preventing Insecure Direct Object References).
- Metadata (filenames, user associations, access rights) is strictly isolated from raw encrypted payloads.

### 2. Alternatives Considered
1. **Alternative 1.1: Plaintext File Storage with OS File-System Permissions**
   - *Description:* Storing cleartext files in a server directory (e.g., `/var/uploads/`) and relying on Linux DAC file permissions (`chmod 600`) and web server routing rules.
   - *Deficiencies:* Any remote code execution (RCE) on the web server, backup misconfiguration, or privilege escalation instantly exposes all documents in cleartext. Zero-trust principles are violated.
2. **Alternative 1.2: Database Binary Storage (MongoDB GridFS / BLOB Columns)**
   - *Description:* Storing unencrypted or server-encrypted binary files directly inside database collections alongside metadata.
   - *Deficiencies:* Massively inflates database memory footprint and backup volume sizes; causes index bloat. A database SQL/NoSQL injection or dump exposes both the files and their structural metadata simultaneously.
3. **Alternative 1.3: Server-Side Transparent Encryption (SSE / Disk Encryption)**
   - *Description:* The server receives cleartext over TLS, encrypts the file before saving to disk, and decrypts it on the fly upon authenticated request.
   - *Deficiencies:* The server process holds the decryption keys in memory. If an attacker gains memory-dump access or root credentials on the API server, all files can be decrypted. Insider threats (system administrators) remain fully unmitigated.
4. **Alternative 1.4: Client-Side Envelope Encryption with Separated Physical Storage Volume (Selected)**
   - *Description:* Documents are encrypted in the client browser prior to transmission. Encrypted files are stored on an isolated volume strictly named with 128-bit random UUIDv4 (`/vault/<uuid>.enc`). All metadata, IVs, tags, and wrapped keys are stored in a separate database collection.

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
- **Limitation:** Inability to perform native server-side full-text search or document indexing without exposing cleartext or deploying complex Searchable Symmetric Encryption (SSE).
- **Trade-off:** Additional client-side CPU utilization for bulk encryption/decryption of very large files (mitigated through hardware-accelerated AES-NI via Web Crypto API).
- **Risk:** Loss of user authentication credentials and local key backup permanently renders the files unrecoverable.

---

## Decision Record 2: Cryptographic Approach and Key Management

### 2.1 The Problem Being Addressed
How to protect confidential document payloads against unauthorized disclosure, bit-flipping, and ciphertext manipulation while providing multi-user access without re-encrypting multi-megabyte payloads for every recipient. Furthermore, private keys must be secured on client devices without being exposed in cleartext to the browser host environment.

### 2.2 Alternatives Considered
1. **Alternative 2.1: Single Master Symmetric Key (Pure AES-CBC)**
   - *Description:* Encrypting all system documents with a single server master AES-256 key in CBC mode.
   - *Deficiencies:* CBC mode is vulnerable to padding oracle attacks (POODLE, Lucky Thirteen) and does not provide built-in ciphertext integrity (malleability/bit-flipping). Key compromise breaches all tenant data.
2. **Alternative 2.2: Pure Asymmetric Encryption (RSA-2048 Direct File Encryption)**
   - *Description:* Encrypting document payloads directly with the recipient's RSA public key.
   - *Deficiencies:* Mathematically constrained: RSA-2048 with OAEP can encrypt a maximum of 214 bytes of data ($2048/8 - 2 \times 32 - 2 = 214$ bytes). Highly inefficient and unsuitable for bulk file data.
3. **Alternative 2.3: Hybrid Envelope Encryption (AES-256-GCM + RSA-OAEP-2048) with Password-Derived KEK (Selected)**
   - *Description:* Each document is encrypted once using a unique, ephemeral 256-bit symmetric Document Encryption Key (DEK) via AES-GCM (Authenticated Encryption with Associated Data). The DEK is then wrapped (encrypted) individually for authorized users using their respective RSA-OAEP 2048-bit public keys. User private keys are protected on the client using a Key Encryption Key (KEK) derived from the user's password via PBKDF2 (SHA-256, 600,000 iterations).

### 2.3 Selected Approach and Justification
**Selected:** Alternative 2.3 — Hybrid Envelope Encryption via Web Crypto API.
- **Justification:**
  - **Authenticated Encryption (AEAD):** AES-256-GCM provides both confidentiality and built-in authenticity via a 128-bit authentication tag. Any unauthorized modification (such as flipping a single bit in the ciphertext) immediately triggers an authentication failure (`OperationError`) in the Web Crypto API, halting decryption before corrupted plaintext can reach the application.
  - **Envelope Key Wrapping Efficiency:** Sharing a 100 MB file with 10 users requires encrypting the 100 MB payload only once. Granting access requires encrypting only a 32-byte DEK into a 256-byte wrapped token, minimizing bandwidth and cryptographic overhead.
  - **Client-Side Key Protection:** The user's RSA private key never leaves the client endpoint in cleartext. It is encrypted in volatile memory with a PBKDF2-derived KEK before being persisted into IndexedDB/localStorage.

### 2.4 Relevant Information Security Concepts
- **Kerckhoffs's Principle:** Security relies solely on the secrecy of the keys, not the obscurity of the algorithm.
- **AEAD (Authenticated Encryption with Associated Data):** Prevents ciphertext tampering, cut-and-paste attacks, and chosen-ciphertext attacks.
- **Key Hierarchy (KEK vs. DEK):** Decouples long-term identity keys from short-term data encryption keys.
- **Hardware Acceleration:** AES-GCM leverages modern CPU instructions (AES-NI and CLMUL) for multi-gigabit per second throughput.

### 2.5 Limitations, Risks, and Trade-offs
- **Limitation:** Inability for system administrators to recover lost files if a user forgets their password and misplaces their local private key backup.
- **Trade-off:** High iteration count for PBKDF2 (600,000 rounds) creates an intentional 200–400ms computational delay during login to deter offline brute-force cracking.
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
  - **Argon2id Memory Hardness:** Standard SHA-256 and MD5 password hashes can be calculated billions of times per second on commodity GPUs. Argon2id requires 64 MB of RAM and multi-threaded computation per hash, rendering parallel GPU and ASIC dictionary attacks mathematically impractical.
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
How to securely share a document with specific authorized recipients without exposing the cleartext to the server, and how to revoke access such that revoked users can neither download future updates nor decrypt previously downloaded offline copies.

### 4.2 Alternatives Considered
1. **Alternative 4.1: Public or Unlisted Signed URLs (e.g., S3 Pre-signed Links)**
   - *Description:* Generating temporary download URLs with access tokens embedded in the query string.
   - *Deficiencies:* Signed URLs can be leaked in browser histories, proxy logs, or forwarded via chat/email. They cannot be revoked selectively without invalidating the signing key.
2. **Alternative 4.2: Server-Proxied Password-Protected Sharing**
   - *Description:* Owner sets a password, which the recipient enters to have the server decrypt and re-encrypt the file.
   - *Deficiencies:* Violates Zero-Trust principles by forcing the server to inspect cleartext. Shared passwords are prone to being sent over insecure out-of-band channels.
3. **Alternative 4.3: Asymmetric Key Wrapping with Dual-Mode Revocation (Selected)**
   - *Description:* To share a document, the owner's client fetches the recipient's RSA public key, decrypts the document's DEK in local volatile memory using the owner's private key, wraps the DEK with the recipient's public key, and sends the resulting 256-byte `wrappedDEK` to be appended to the document's ACL in the database. Revocation provides two distinct tiers:
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
3. **Alternative 5.3: Cryptographic SHA-256 Hash-Chained Append-Only Ledger (Selected)**
   - *Description:* Every security event is formatted as an immutable block cryptographically bound to the previous block via a SHA-256 hash pointer:
     $$\text{CurrHash} = \text{SHA256}(\text{PrevHash} \parallel \text{Timestamp} \parallel \text{ActorId} \parallel \text{Action} \parallel \text{TargetDocId} \parallel \text{Outcome})$$
     The ledger begins with a deterministic Genesis Block (`prevHash: 000...000`). An automated integrity verification routine recalculates the chain from index $0$ to $N$. If any historical record is altered, inserted, or deleted, the mathematical hash link breaks at that exact block index.

### 5.3 Selected Approach and Justification
**Selected:** Alternative 5.3 — Cryptographic SHA-256 Hash-Chained Append-Only Ledger.
- **Justification:**
  - **Mathematical Proof of Integrity:** Any alteration of an existing record changes its calculated SHA-256 digest, which immediately creates a mismatch with the `prevHash` of the subsequent block.
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

## Summary Matrix of Major Architectural Decisions

| # | Decision Area | Selected Mechanism | Key Security Justification | Primary Trade-off |
|---|---------------|--------------------|----------------------------|-------------------|
| **1** | **Document Storage** | Separated `/vault/<uuid>.enc` Blob Vault + Metadata DB | Minimizes blast radius; renders drive dumps useless (high entropy) | No server-side cleartext full-text indexing |
| **2** | **Cryptographic Protection** | Client-Side Envelope Encryption (AES-256-GCM + RSA-OAEP-2048) | AEAD prevents tampering; zero-knowledge server; lightweight sharing | Lost passwords/keys cannot be recovered by admins |
| **3** | **Auth & Access Control** | Argon2id + HttpOnly JWT + Hybrid RBAC/DAC | Resists GPU/ASIC brute forcing; eliminates IDOR via server-side PEP | Per-request ACL evaluation in database |
| **4** | **Sharing & Revocation** | Public Key DEK Wrapping + Dual-Tier Revocation | Instant server-side cutoff; cryptographic re-encryption prevents offline leaks | Cryptographic revocation requires client re-upload |
| **5** | **Auditing & Accountability**| SHA-256 Hash-Chained Append-Only Ledger | Mathematical tamper evidence; non-repudiation; detection of DB modification | Requires WORM storage to prevent total database drops |

---
*End of Design Decision Record (CS3002 — FAST-NUCES)*
