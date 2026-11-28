require('dotenv').config();
const crypto = require('crypto');
const db = require('./database');
const pep = require('./pep');
const auditChain = require('./auditChain');

async function seedDefaultUsers() {
  try {
    await db.connect();
    let hash = null;

    const demoUsers = [
      {
        id: 'usr_mashaf',
        username: 'mashaf',
        fullName: 'Syed Muhammad Mashaf Zaidi',
        email: 'mashaf@vaultora.io',
        role: 'admin'
      },
      {
        id: 'usr_ali',
        username: 'ali',
        fullName: 'Ali Raza',
        email: 'ali@vaultora.io',
        role: 'user'
      },
      {
        id: 'usr_farman',
        username: 'farman',
        fullName: 'Farman Ahmed',
        email: 'farman@vaultora.io',
        role: 'user'
      }
    ];

    for (const u of demoUsers) {
      const existing = await db.findUserByUsername(u.username);
      if (!existing) {
        if (!hash) {
          hash = await pep.hashPassword('Password123!');
        }
        const { publicKey } = crypto.generateKeyPairSync('rsa', {
          modulusLength: 2048,
          publicKeyEncoding: { type: 'spki', format: 'pem' }
        });

        const created = await db.createUser({
          id: u.id,
          username: u.username,
          fullName: u.fullName,
          email: u.email,
          role: u.role,
          argon2Hash: hash,
          publicKeyPem: publicKey,
          createdAt: new Date()
        });

        await auditChain.recordEvent({
          actorId: created.id,
          actorName: created.fullName,
          actorRole: created.role,
          action: 'USER_REGISTRATION',
          outcome: 'SUCCESS',
          details: {
            username: created.username,
            role: created.role,
            type: 'System Seed Initial User',
            note: 'CS3002 Demo Account'
          }
        });

        console.log(`✓ Created demo account in MongoDB: ${u.fullName} (@${u.username}) [${u.role}]`);
      } else {
        console.log(`- Account already exists in MongoDB: @${u.username}`);
      }
    }
  } catch (err) {
    console.error('Error seeding demo users:', err);
  }
}

module.exports = seedDefaultUsers;

if (require.main === module) {
  seedDefaultUsers().then(() => process.exit(0));
}
