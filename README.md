# Vaultora — Zero-Trust Secure Document Management System
**CS3002 Information Security — Semester Project**  
**National University of Computer & Emerging Sciences (FAST-NUCES)**  
**Author:** Syed Muhammad Mashaf Zaidi (Roll No: 23F-0529)  

---

## Overview
**Vaultora** is an enterprise-grade Secure Document Management System engineered under a strict **Zero-Trust Hybrid-Encrypted Architecture**. The application server and database act as blind relays, handling only encrypted ciphertext and public-key-wrapped symmetric keys. Plaintext document contents and private cryptographic keys never touch the network or the backend server.

---

## Key Features & Architecture Implementation (Part 2)

### 1. Client-Side Cryptographic Engine (Web Crypto API)
- **Key Generation:** Generates asymmetric `RSA-OAEP-2048` keypairs on the client. Public keys are registered for user discovery; private keys are encrypted locally using a password-derived Key Encryption Key (KEK) via `PBKDF2` (SHA-256, 600,000 iterations).
- **Envelope Encryption:** Every document upload generates an ephemeral, cryptographically secure 256-bit symmetric Document Encryption Key (`DEK`) and a 12-byte random `IV`.
- **Payload Protection:** Files are encrypted client-side using `AES-256-GCM` (producing ciphertext and a 16-byte authentication tag). A client-side `SHA-256` digest is also calculated before encryption.
- **Envelope Wrapping:** The 256-bit DEK is encrypted with the user's RSA-OAEP public key (`Wrapped_DEK`).

### 2. Physical Storage & Metadata Isolation
- **Storage Vault (`/vault/<uuid>.enc`):** Binary storage volume holds strictly random UUIDv4-named files containing raw, high-entropy AES-GCM ciphertext. No original filenames, extensions, or metadata exist on disk.
- **Metadata Database (`/backend/data/`):** Dedicated document store maintaining access vectors, IVs, authentication tags, SHA-256 checksums, and RSA-wrapped DEKs.

### 3. Identity & Dual-Layer Access Control (PEP)
- **Authentication:** Memory-hard `Argon2id` password hashing ($m=65536, t=3, p=4$) combined with signed JSON Web Tokens (JWT) transmitted via `HttpOnly`, `SameSite=Strict` secure session cookies.
- **Hybrid RBAC + DAC:**
  - **RBAC:** Controls administrative actions, audit verification, and user management.
  - **DAC (Document ACL):** Evaluates access requests against per-document ACLs (`owner`, `editor`, `viewer`) with support for temporal expiration (`expiresAt`). Completely prevents Insecure Direct Object Reference (IDOR) attacks.

### 4. Controlled Document Sharing & Revocation
- **Asymmetric Key Wrapping:** Document owners decrypt the DEK in browser memory and wrap it with the recipient's RSA public key.
- **Dual-Mode Revocation:**
  - *Standard Revocation:* Immediate server-side removal of the recipient's ACL entry, blocking subsequent API calls.
  - *Cryptographic Revocation:* Client re-encrypts the document with a fresh DEK, re-wraps it only for remaining authorized recipients, and overwrites the vault ciphertext.

### 5. Tamper-Evident Hash-Chained Audit Ledger
- Append-only cryptographic ledger linking every security event:
  $$\text{currHash} = \text{SHA256}(\text{prevHash} \parallel \text{timestamp} \parallel \text{actorId} \parallel \text{action} \parallel \text{targetDocId} \parallel \text{outcome})$$
- Starts with a deterministic Genesis Block (`0000000000000000...`).
- Built-in verification engine recalculates the chain and flags the exact block index of any unauthorized modification or deletion.

---

## Frontend Design (Pixel-Matched to Design Mockup)
The user interface matches the provided **Vaultora Secure Workspace** design:
- Dark navy sidebar (`#0c1527`) with active blue indicator, badges (`24`, `7`), and storage allocation bar.
- Top navigation with real-time search, notification indicator, and user profile pill (`AM - Areeba Malik, Administrator`).
- 4 Metric Stat Cards:
  1. **Total documents:** 24 (+3 this month)
  2. **Shared with you:** 07 (2 new invitations)
  3. **Protected files:** 24 (100% encrypted)
  4. **Storage used:** 68% (3.2 GB available)
- Recent Documents Table with file type icons, metadata, owner badges, sharing avatar stacks, and actions menu.
- **Security Status Card:** Workspace security level with green indicators and a direct link to the Security Center.
- **Recent Activity Feed:** Real-time stream of audit events.

---

## Project Structure
```
vaultora/
├── backend/
│   ├── data/
│   │   ├── users.json           # User profiles, Argon2id hashes, Public Keys
│   │   ├── documents.json       # Document metadata, IV, Tag, SHA-256, ACLs
│   │   └── audit_logs.json      # Cryptographic SHA-256 chained audit ledger
│   ├── auditChain.js            # Cryptographic hash chain engine & verifier
│   ├── database.js              # Atomic JSON document store operations
│   ├── pep.js                   # Policy Enforcement Point & Argon2id auth
│   ├── storage.js               # Physical /vault/ storage & entropy inspector
│   ├── server.js                # Express API & static frontend server
│   ├── seedData.js              # Initial demo data & vault blobs
│   └── package.json
├── frontend/
│   ├── src/
│   │   ├── App.jsx              # Vaultora workspace dashboard matching mockup
│   │   ├── cryptoEngine.js      # Web Crypto API (AES-GCM, RSA-OAEP, PBKDF2)
│   │   ├── main.jsx             # React entrypoint
│   │   └── index.css            # Tailwind CSS v4 styling
│   ├── vite.config.js           # Vite configuration & backend proxy
│   └── package.json
├── vault/                       # Physical disk volume storing <uuid>.enc blobs
├── DESIGN_DECISION_RECORD.md    # Part 4: Complete Design Decision Record (5 Areas)
└── README.md
```

---

## Setup & Running the Application

### 1. Prerequisites
- **Node.js** (v18+ recommended)
- **npm** (v9+)

### 2. Quick Start
To start the unified server (which serves both the API and the React frontend on port `5000`):

```bash
# Navigate to the backend directory
cd backend

# Start the server
node server.js
```

Open your browser and navigate to:
**`http://localhost:5000`**

*(Alternatively, to run the Vite development server independently with hot-reloading: `cd frontend && npm run dev`, accessible at `http://localhost:3000`)*.

---

## Default Demo Credentials

| Full Name | Username | Password | System Role |
|-----------|----------|----------|-------------|
| **Areeba Malik** | `areeba` | `Password123!` | **Administrator** |
| **Omar Khan** | `omar` | `Password123!` | Standard User |
| **Sarah Ali** | `sarah` | `Password123!` | Standard User |

---

## Verifying Security & Adversarial Scenarios

The system includes built-in interactive features to demonstrate and verify all security properties:

1. **Storage Exposure Verification:**
   - In the document menu (`...`), click **"Inspect Vault Disk Blob"**.
   - The system inspects `/vault/<uuid>.enc` directly on disk, displays its Shannon entropy ($\approx 7.99$ / 8.00 bits/byte), raw hex samples, and proves zero plaintext or metadata exists on the drive.

2. **Tamper Detection (Ciphertext Bit-Flipping):**
   - In the document menu (`...`), click **"Simulate Bit-Flip Tamper"**.
   - The backend flips bit 0 of the stored `.enc` file.
   - When any user attempts to download and decrypt the file, the browser's Web Crypto API detects that the AES-GCM 16-byte authentication tag does not match, immediately aborting decryption and throwing an integrity verification alert.

3. **Audit Ledger Verification & Tamper Detection:**
   - Click **"View security center"** in the sidebar or right panel.
   - Click **"Verify Hash-Chain Integrity"**: The backend verifies every block from genesis to the latest record and reports all hashes valid.
   - Click **"Simulate Audit Tampering"**: The backend alters a historical log entry.
   - Re-running **"Verify Hash-Chain Integrity"** immediately flags the exact block index where the hash chain was severed.

---
*End of README — CS3002 FAST-NUCES*
