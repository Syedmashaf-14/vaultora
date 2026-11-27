// Web Crypto API Engine for Vaultora
// Core Studied Algorithms: AES-256-GCM, RSA-OAEP-2048, SHA-512, Diffie-Hellman, PBKDF2 (SHA-512), DES & ElGamal References

// Helper: ArrayBuffer to Base64
export function bufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

// Helper: Base64 to ArrayBuffer
export function base64ToBuffer(base64) {
  const binary = window.atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// Helper: ArrayBuffer to Hex string
export function bufferToHex(buffer) {
  const bytes = new Uint8Array(buffer);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Convert SPKI ArrayBuffer to PEM string
export function spkiToPEM(spkiBuffer) {
  const b64 = bufferToBase64(spkiBuffer);
  let pem = '-----BEGIN PUBLIC KEY-----\n';
  for (let i = 0; i < b64.length; i += 64) {
    pem += b64.substring(i, i + 64) + '\n';
  }
  pem += '-----END PUBLIC KEY-----';
  return pem;
}

// Convert PEM string to SPKI ArrayBuffer
export function pemToSpki(pem) {
  const b64 = pem
    .replace('-----BEGIN PUBLIC KEY-----', '')
    .replace('-----END PUBLIC KEY-----', '')
    .replace(/\s+/g, '');
  return base64ToBuffer(b64);
}

// 1. Generate RSA-OAEP 2048-bit Keypair for User (Asymmetric Encryption)
export async function generateUserKeyPair() {
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256'
    },
    true,
    ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
  );

  const spki = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
  const publicKeyPem = spkiToPEM(spki);

  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
    publicKeyPem
  };
}

// 2. Import Public Key from PEM
export async function importPublicKey(pem) {
  const spkiBuffer = pemToSpki(pem);
  return await window.crypto.subtle.importKey(
    'spki',
    spkiBuffer,
    {
      name: 'RSA-OAEP',
      hash: 'SHA-256'
    },
    true,
    ['encrypt', 'wrapKey']
  );
}

// 3. PBKDF2 Password-based Key Derivation (KEK) using SHA-512 (600,000 iterations)
export async function deriveKEK(password, salt) {
  const enc = new TextEncoder();
  const passwordKey = await window.crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  return await window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: 600000,
      hash: 'SHA-512' // Using course-studied SHA-512
    },
    passwordKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
  );
}

// Encrypt Private Key with KEK and store in Local Storage
export async function encryptAndStorePrivateKey(privateKey, password, userId) {
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const kek = await deriveKEK(password, salt);

  const exportedPKCS8 = await window.crypto.subtle.exportKey('pkcs8', privateKey);

  const encryptedKeyBuffer = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    kek,
    exportedPKCS8
  );

  const keyRecord = {
    userId,
    saltBase64: bufferToBase64(salt),
    ivBase64: bufferToBase64(iv),
    encryptedKeyBase64: bufferToBase64(encryptedKeyBuffer)
  };

  localStorage.setItem(`vaultora_key_${userId}`, JSON.stringify(keyRecord));
  return keyRecord;
}

// Decrypt Private Key using Password
export async function loadAndDecryptPrivateKey(password, userId) {
  const recordStr = localStorage.getItem(`vaultora_key_${userId}`);
  if (!recordStr) {
    throw new Error('No local private key found on this client.');
  }

  const record = JSON.parse(recordStr);
  const salt = new Uint8Array(base64ToBuffer(record.saltBase64));
  const iv = new Uint8Array(base64ToBuffer(record.ivBase64));
  const encryptedBytes = base64ToBuffer(record.encryptedKeyBase64);

  const kek = await deriveKEK(password, salt);

  try {
    const decryptedPKCS8 = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      kek,
      encryptedBytes
    );

    return await window.crypto.subtle.importKey(
      'pkcs8',
      decryptedPKCS8,
      {
        name: 'RSA-OAEP',
        hash: 'SHA-256'
      },
      true,
      ['decrypt', 'unwrapKey']
    );
  } catch {
    throw new Error('Failed to decrypt private key. Incorrect local password.');
  }
}

// 4. Document Encryption (Hybrid Envelope: AES-256-GCM + RSA-OAEP + SHA-512)
export async function encryptDocument(fileBuffer, ownerPublicKey) {
  // 1. Calculate SHA-512 of plaintext
  const hashBuffer = await window.crypto.subtle.digest('SHA-512', fileBuffer);
  const sha512Hex = bufferToHex(hashBuffer);

  // 2. Generate random 256-bit symmetric DEK (AES)
  const dek = await window.crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );

  // 3. Generate 12-byte random IV
  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  // 4. Encrypt file with AES-256-GCM (produces ciphertext + 16-byte tag appended)
  const fullEncryptedBuffer = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    dek,
    fileBuffer
  );

  const totalLength = fullEncryptedBuffer.byteLength;
  const tagLength = 16;
  const authTagBytes = fullEncryptedBuffer.slice(totalLength - tagLength);

  // 5. Export raw DEK
  const rawDEK = await window.crypto.subtle.exportKey('raw', dek);

  // 6. Wrap DEK with Owner RSA Public Key
  const wrappedDEKBuffer = await window.crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    ownerPublicKey,
    rawDEK
  );

  return {
    encryptedBlob: new Blob([fullEncryptedBuffer], { type: 'application/octet-stream' }),
    ivBase64: bufferToBase64(iv),
    authTagBase64: bufferToBase64(authTagBytes),
    sha512Hex,
    sha256Hex: sha512Hex, // For backwards compatibility
    wrappedDEKBase64: bufferToBase64(wrappedDEKBuffer),
    rawDEK
  };
}

// 5. Document Decryption (Client-side verification of AEAD tag + SHA-512)
export async function decryptDocument(
  encryptedBuffer,
  ivBase64,
  authTagBase64,
  expectedChecksumHex,
  wrappedDEKBase64,
  userPrivateKey
) {
  // 1. Unwrap DEK using User RSA Private Key
  const wrappedDEKBuffer = base64ToBuffer(wrappedDEKBase64);
  let rawDEK;
  try {
    rawDEK = await window.crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      userPrivateKey,
      wrappedDEKBuffer
    );
  } catch (err) {
    throw new Error('Failed to unwrap DEK: RSA-OAEP private key mismatch or corrupted key wrapper.');
  }

  // 2. Import raw DEK as AES-GCM key
  const dek = await window.crypto.subtle.importKey(
    'raw',
    rawDEK,
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  );

  // 3. Decrypt ciphertext using AES-256-GCM
  const iv = new Uint8Array(base64ToBuffer(ivBase64));

  let decryptedBuffer;
  try {
    decryptedBuffer = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      dek,
      encryptedBuffer
    );
  } catch (err) {
    throw new Error('Integrity Verification Failed: AES-GCM authentication tag mismatch or corrupted ciphertext (bit-flipping detected!).');
  }

  // 4. Verify plaintext SHA-512 hash against metadata
  const plaintextHashBuffer = await window.crypto.subtle.digest('SHA-512', decryptedBuffer);
  const actualSha512Hex = bufferToHex(plaintextHashBuffer);

  if (expectedChecksumHex && actualSha512Hex !== expectedChecksumHex) {
    // Check fallback for SHA-256 legacy uploads
    const sha256Buffer = await window.crypto.subtle.digest('SHA-256', decryptedBuffer);
    const actualSha256Hex = bufferToHex(sha256Buffer);
    if (actualSha256Hex !== expectedChecksumHex) {
      throw new Error(`SHA-512 Checksum Mismatch! Expected ${expectedChecksumHex.substring(0, 16)}..., computed ${actualSha512Hex.substring(0, 16)}...`);
    }
  }

  return {
    decryptedBuffer,
    verifiedSha512: actualSha512Hex,
    rawDEK
  };
}

// 6. Wrap DEK for a New Recipient (RSA Public Key)
export async function wrapDEKForRecipient(rawDEK, recipientPublicKeyPem) {
  const recipientPublicKey = await importPublicKey(recipientPublicKeyPem);
  const wrapped = await window.crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    recipientPublicKey,
    rawDEK
  );
  return bufferToBase64(wrapped);
}

// 7. Diffie-Hellman Key Agreement Engine (Studied Course Algorithm)
export async function generateDiffieHellmanKeyPair() {
  return await window.crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-384' },
    true,
    ['deriveKey', 'deriveBits']
  );
}

export async function deriveDiffieHellmanSharedKey(privateKey, otherPartyPublicKey) {
  return await window.crypto.subtle.deriveKey(
    { name: 'ECDH', public: otherPartyPublicKey },
    privateKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}
