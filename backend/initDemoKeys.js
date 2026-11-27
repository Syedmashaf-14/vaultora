require('dotenv').config();
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const db = require('./database');

function generateDemoKeyRecord(userId, password = 'Password123!') {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' }
  });

  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);

  // Derive KEK via PBKDF2 (SHA-512, 600,000 iterations)
  const kek = crypto.pbkdf2Sync(password, salt, 600000, 32, 'sha512');

  // Encrypt privateKey with AES-256-GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', kek, iv);
  const encryptedKey = Buffer.concat([cipher.update(privateKey), cipher.final(), cipher.getAuthTag()]);

  return {
    record: {
      userId,
      saltBase64: salt.toString('base64'),
      ivBase64: iv.toString('base64'),
      encryptedKeyBase64: encryptedKey.toString('base64'),
      publicKeyPem: publicKey
    },
    publicKeyPem: publicKey
  };
}

async function init() {
  console.log('Connecting to MongoDB Atlas...');
  await db.connect();

  const demoKeyMap = {};
  const users = ['usr_mashaf', 'usr_ali', 'usr_farman'];

  for (const uid of users) {
    console.log(`Generating matching RSA keypair for ${uid}...`);
    const { record, publicKeyPem } = generateDemoKeyRecord(uid);
    demoKeyMap[uid] = record;

    await db.updateUser(uid, { publicKeyPem });
    console.log(`✓ Synchronized ${uid} public key to MongoDB Atlas.`);
  }

  // Clear stale test documents uploaded prior to key synchronization
  const staleDocs = await db.getDocuments();
  for (const doc of staleDocs) {
    console.log(`Removing stale document ${doc.originalName} (${doc.id})...`);
    await db.deleteDoc(doc.id);
    const encPath = path.join(__dirname, '..', doc.storagePath.replace(/^\//, ''));
    if (fs.existsSync(encPath)) {
      fs.unlinkSync(encPath);
      console.log(`✓ Deleted ciphertext file: ${encPath}`);
    }
  }

  // Write demoKeys.json to frontend
  const outPath = path.join(__dirname, '..', 'frontend', 'src', 'demoKeys.json');
  fs.writeFileSync(outPath, JSON.stringify(demoKeyMap, null, 2), 'utf8');
  console.log(`✓ Saved demo keys bundle to ${outPath}`);

  console.log('Demo key initialization complete!');
  process.exit(0);
}

init().catch(err => {
  console.error('Error during initDemoKeys:', err);
  process.exit(1);
});
