require('dotenv').config();
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const path = require('path');
const { randomUUID: uuidv4 } = require('crypto');

const db = require('./database');
const auditChain = require('./auditChain');
const storage = require('./storage');
const pep = require('./pep');

const app = express();
const PORT = process.env.PORT || 5000;

// Trust proxy headers (needed on Vercel / reverse proxies for req.secure / HTTPS cookies)
app.set('trust proxy', 1);

// Setup Multer memory storage for incoming encrypted payloads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 100 * 1024 * 1024 } // 100MB local (note: Vercel caps request bodies at ~4.5MB)
});

// Middleware
app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (
      origin.startsWith('http://localhost:') ||
      origin.startsWith('http://127.0.0.1:') ||
      origin.endsWith('.vercel.app') ||
      (process.env.FRONTEND_URL && origin === process.env.FRONTEND_URL)
    ) {
      return callback(null, true);
    }
    return callback(null, true);
  },
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());

function getCookieOptions(req) {
  const isHttps = req.secure || req.headers['x-forwarded-proto'] === 'https' || process.env.VERCEL === '1';
  return {
    httpOnly: true,
    secure: isHttps,
    sameSite: 'strict',
    maxAge: 2 * 60 * 60 * 1000 // 2 hours
  };
}

// Enforce security headers on all responses
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});

// Serverless-safe lazy DB & seed initialization (cached across warm invocations)
const seedDefaultUsers = require('./seedData');
let initPromise = null;
async function ensureInitialized() {
  if (!initPromise) {
    initPromise = (async () => {
      await db.connect();
      await seedDefaultUsers();
    })().catch(err => {
      initPromise = null;
      throw err;
    });
  }
  return initPromise;
}

app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    vercel: Boolean(process.env.VERCEL),
    hasMongoUri: Boolean(process.env.MONGODB_URI),
    dbConnected: db.isUsingMongoose()
  });
});

app.use('/api', async (req, res, next) => {
  try {
    await ensureInitialized();
    next();
  } catch (err) {
    console.error('Database initialization error:', err);
    res.status(500).json({ error: 'Database connection failed.', details: err.message });
  }
});

// ==========================================
// 1. AUTHENTICATION ENDPOINTS (MONGODB)
// ==========================================

// Register User
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, fullName, password, publicKeyPem, role = 'user' } = req.body || {};

    if (
      typeof username !== 'string' ||
      typeof email !== 'string' ||
      typeof password !== 'string' ||
      typeof publicKeyPem !== 'string' ||
      !username.trim() ||
      !email.trim() ||
      !password ||
      !publicKeyPem.trim()
    ) {
      return res.status(400).json({ error: 'Username, email, password, and RSA public key are required.' });
    }

    const cleanUsername = username.trim().toLowerCase();
    const cleanEmail = email.trim().toLowerCase();
    const cleanFullName = typeof fullName === 'string' && fullName.trim() ? fullName.trim() : cleanUsername;

    const emailRegex = /^[a-zA-Z0-9](?:[a-zA-Z0-9._%+-]*[a-zA-Z0-9])?@(?:[a-zA-Z0-9-]*[a-zA-Z][a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}$/;
    const usernameRegex = /^[a-z0-9_]{3,24}$/;

    if (cleanFullName.length < 2 || cleanFullName.length > 60) {
      return res.status(400).json({ error: 'Full name must be between 2 and 60 characters.' });
    }

    if (cleanEmail.includes('..') || !emailRegex.test(cleanEmail)) {
      return res.status(400).json({ error: 'Please enter a valid email address (e.g., name@gmail.com).' });
    }

    if (!usernameRegex.test(cleanUsername)) {
      return res.status(400).json({ error: 'Username must be 3-24 characters (letters, numbers, underscores only).' });
    }

    if (password.length < 8 || !/[A-Za-z]/.test(password) || !/[0-9]/.test(password)) {
      return res.status(400).json({ error: 'Password must be at least 8 characters and include a letter and a number.' });
    }

    if (!publicKeyPem.includes('BEGIN PUBLIC KEY')) {
      return res.status(400).json({ error: 'Invalid RSA public key format.' });
    }

    const existingUser = await db.findUserByUsername(cleanUsername);
    if (existingUser) {
      return res.status(409).json({ error: 'Username is already registered.' });
    }
    const existingEmail = await db.findUserByEmail(cleanEmail);
    if (existingEmail) {
      return res.status(409).json({ error: 'Email address is already in use.' });
    }

    const argon2Hash = await pep.hashPassword(password);
    const userId = `usr_${uuidv4().substring(0, 8)}`;

    const newUser = {
      id: userId,
      username: cleanUsername,
      email: cleanEmail,
      fullName: cleanFullName,
      role: ['admin', 'auditor', 'user'].includes(role) ? role : 'user',
      argon2Hash,
      publicKeyPem,
      createdAt: new Date().toISOString()
    };

    const created = await db.createUser(newUser);

    await auditChain.recordEvent({
      actorId: created.id,
      actorName: created.fullName,
      actorRole: created.role,
      action: 'USER_REGISTRATION',
      outcome: 'SUCCESS',
      details: {
        username: created.username,
        email: created.email,
        role: created.role,
        storageEngine: 'MongoDB Cluster',
        algorithm: 'Argon2id + RSA-OAEP-2048'
      }
    });

    const token = pep.generateToken(created);
    res.cookie('jwt', token, getCookieOptions(req));

    res.status(201).json({
      message: 'Account created successfully in MongoDB cluster.',
      user: {
        id: created.id,
        username: created.username,
        email: created.email,
        fullName: created.fullName,
        role: created.role,
        publicKeyPem: created.publicKeyPem
      }
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Registration failed.', details: err.message });
  }
});
// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required.' });
    }

    const user = await db.findUserByUsername(username);
    if (!user) {
      await auditChain.recordEvent({
        actorId: 'UNKNOWN',
        actorName: username,
        action: 'USER_LOGIN',
        outcome: 'FAILED',
        details: { reason: 'User not found in MongoDB' }
      });
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    const valid = await pep.verifyPassword(user.argon2Hash, password);
    if (!valid) {
      await auditChain.recordEvent({
        actorId: user.id,
        actorName: user.fullName,
        actorRole: user.role,
        action: 'USER_LOGIN',
        outcome: 'FAILED',
        details: { reason: 'Password verification failed via Argon2id' }
      });
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    await auditChain.recordEvent({
      actorId: user.id,
      actorName: user.fullName,
      actorRole: user.role,
      action: 'USER_LOGIN',
      outcome: 'SUCCESS',
      details: { role: user.role }
    });

    const token = pep.generateToken(user);
    res.cookie('jwt', token, getCookieOptions(req));

    res.json({
      message: 'Login successful',
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        fullName: user.fullName,
        role: user.role,
        publicKeyPem: user.publicKeyPem
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed.', details: err.message });
  }
});

// Logout
app.post('/api/auth/logout', pep.authenticate, async (req, res) => {
  await auditChain.recordEvent({
    actorId: req.user.id,
    actorName: req.user.fullName,
    actorRole: req.user.role,
    action: 'USER_LOGOUT',
    outcome: 'SUCCESS'
  });
  const opts = getCookieOptions(req);
  res.clearCookie('jwt', { httpOnly: opts.httpOnly, secure: opts.secure, sameSite: opts.sameSite });
  res.json({ message: 'Logged out successfully.' });
});

// Get Current Profile
app.get('/api/auth/me', pep.authenticate, (req, res) => {
  res.json({
    user: {
      id: req.user.id,
      username: req.user.username,
      email: req.user.email,
      fullName: req.user.fullName,
      role: req.user.role,
      publicKeyPem: req.user.publicKeyPem
    }
  });
});

// Sync / Update Client Public Key in MongoDB
app.post('/api/auth/sync-key', pep.authenticate, async (req, res) => {
  try {
    const { publicKeyPem } = req.body;
    if (!publicKeyPem) {
      return res.status(400).json({ error: 'Public key PEM is required.' });
    }
    await db.updateUser(req.user.id, { publicKeyPem });
    res.json({ message: 'Client public key synchronized successfully in MongoDB.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Discover Users for Sharing (Returns public keys)
app.get('/api/auth/users', pep.authenticate, async (req, res) => {
  const users = await db.getUsers();
  res.json({
    users: users.map(u => ({
      id: u.id,
      username: u.username,
      fullName: u.fullName,
      role: u.role,
      publicKeyPem: u.publicKeyPem
    }))
  });
});

// ==========================================
// 2. DOCUMENT MANAGEMENT ENDPOINTS
// ==========================================

// Upload Encrypted Document
app.post('/api/documents/upload', pep.authenticate, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'Encrypted ciphertext payload is required.' });
    }

    const {
      originalName,
      fileType,
      iv,
      authTag,
      sha512,
      sha256,
      wrappedDEK
    } = req.body;

    const fileChecksum = sha512 || sha256;
    if (!originalName || !iv || !authTag || !fileChecksum || !wrappedDEK) {
      return res.status(400).json({
        error: 'Missing required cryptographic envelope fields (iv, authTag, sha512, wrappedDEK).'
      });
    }

    const docId = uuidv4();

    // Save pure ciphertext in isolated vault storage (MongoDB GridFS or /vault/)
    await storage.saveEncryptedBlob(docId, req.file.buffer);

    const newDoc = {
      id: docId,
      originalName,
      fileType: fileType || path.extname(originalName).replace('.', '') || 'bin',
      size: req.file.size,
      ownerId: req.user.id,
      ownerName: req.user.fullName,
      iv,
      authTag,
      sha512: fileChecksum,
      sha256: fileChecksum,
      storagePath: `/vault/${docId}.enc`,
      wrappedDEKs: [
        {
          userId: req.user.id,
          userName: req.user.fullName,
          wrappedKey: wrappedDEK,
          permission: 'owner',
          grantedAt: new Date(),
          expiresAt: null
        }
      ]
    };

    const savedDoc = await db.createDoc(newDoc);

    await auditChain.recordEvent({
      actorId: req.user.id,
      actorName: req.user.fullName,
      actorRole: req.user.role,
      action: 'DOCUMENT_UPLOAD',
      targetDocId: savedDoc.id,
      targetDocName: savedDoc.originalName,
      outcome: 'SUCCESS',
      details: {
        sizeBytes: savedDoc.size,
        blobPath: savedDoc.storagePath,
        sha512Checksum: savedDoc.sha512 || savedDoc.sha256
      }
    });

    res.status(201).json({
      message: 'Document encrypted and stored successfully in MongoDB and Vault volume.',
      document: savedDoc
    });
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: 'Failed to upload document.', details: err.message });
  }
});

// Helper: Auto-purge expired temporary access entries (NOT sent to trash)
async function pruneExpiredAccess() {
  try {
    const allDocs = await db.getDocuments();
    const now = new Date();
    const cleanedDocs = [];

    for (const doc of allDocs) {
      let changed = false;
      const validDEKs = [];
      const expiredEntries = [];

      for (const entry of (doc.wrappedDEKs || [])) {
        // Owner never expires; check recipients with expiresAt
        if (entry.userId !== doc.ownerId && entry.expiresAt && now > new Date(entry.expiresAt)) {
          expiredEntries.push(entry);
          changed = true;
        } else {
          validDEKs.push(entry);
        }
      }

      if (changed) {
        let starredBy = Array.isArray(doc.starredBy) ? [...doc.starredBy] : [];
        let archivedBy = Array.isArray(doc.archivedBy) ? [...doc.archivedBy] : [];
        let trashedBy = Array.isArray(doc.trashedBy) ? [...doc.trashedBy] : [];

        for (const exp of expiredEntries) {
          starredBy = starredBy.filter(id => id !== exp.userId);
          archivedBy = archivedBy.filter(id => id !== exp.userId);
          trashedBy = trashedBy.filter(id => id !== exp.userId);

          await auditChain.recordEvent({
            actorId: exp.userId,
            actorName: exp.userName || exp.userId,
            actorRole: 'system',
            action: 'TEMPORARY_ACCESS_EXPIRED',
            targetDocId: doc.id,
            targetDocName: doc.originalName,
            outcome: 'SUCCESS',
            details: {
              expiredAt: exp.expiresAt,
              autoAction: 'Permanently removed from user access list (bypassed Trash)'
            }
          });
        }

        const deletedBy = Array.isArray(doc.deletedBy) ? doc.deletedBy : [];
        const remainingHolders = validDEKs.filter(w => !deletedBy.includes(w.userId));

        if (remainingHolders.length === 0) {
          await storage.deleteEncryptedBlob(doc.id);
          await db.deleteDoc(doc.id);
          continue; // Document completely purged
        } else {
          const updated = await db.updateDoc(doc.id, {
            wrappedDEKs: validDEKs,
            starredBy,
            archivedBy,
            trashedBy
          });
          cleanedDocs.push(updated || { ...doc, wrappedDEKs: validDEKs, starredBy, archivedBy, trashedBy });
          continue;
        }
      }

      cleanedDocs.push(doc);
    }

    return cleanedDocs;
  } catch (err) {
    console.error('Error pruning expired access:', err);
    return await db.getDocuments();
  }
}

// Helper: Remove/delete document for a specific user (Owner OR Recipient)
// Physically purges encrypted blob & DB doc ONLY when zero holders remain.
async function deleteDocumentForUser(doc, user) {
  const userId = user.id;
  const remainingDEKs = (doc.wrappedDEKs || []).filter(w => w.userId !== userId);
  const deletedBy = Array.isArray(doc.deletedBy) ? [...doc.deletedBy] : [];
  if (!deletedBy.includes(userId)) deletedBy.push(userId);

  const starredBy = (doc.starredBy || []).filter(id => id !== userId);
  const archivedBy = (doc.archivedBy || []).filter(id => id !== userId);
  const trashedBy = (doc.trashedBy || []).filter(id => id !== userId);

  const activeHolders = remainingDEKs.filter(w => !deletedBy.includes(w.userId));

  if (activeHolders.length === 0) {
    await storage.deleteEncryptedBlob(doc.id);
    await db.deleteDoc(doc.id);
  } else {
    await db.updateDoc(doc.id, {
      wrappedDEKs: remainingDEKs,
      deletedBy,
      starredBy,
      archivedBy,
      trashedBy
    });
  }

  await auditChain.recordEvent({
    actorId: user.id,
    actorName: user.fullName,
    actorRole: user.role,
    action: activeHolders.length === 0 ? 'DOCUMENT_PURGED' : 'USER_COPY_DELETED',
    targetDocId: doc.id,
    targetDocName: doc.originalName,
    outcome: 'SUCCESS',
    details: {
      sizeBytes: doc.size,
      remainingHoldersCount: activeHolders.length
    }
  });
}

// List Documents Accessible to Current User
app.get('/api/documents', pep.authenticate, async (req, res) => {
  const allDocs = await pruneExpiredAccess();
  const userId = req.user.id;

  // Filter documents accessible to user (not deleted by them, and in ACL or owner)
  const accessibleDocs = allDocs.filter(d => {
    const deletedBy = Array.isArray(d.deletedBy) ? d.deletedBy : [];
    if (deletedBy.includes(userId)) return false;

    if (d.ownerId === userId) return true;
    return d.wrappedDEKs && d.wrappedDEKs.some(w => w.userId === userId);
  });

  const mappedDocs = accessibleDocs.map(d => {
    const myAcl = d.wrappedDEKs ? d.wrappedDEKs.find(w => w.userId === userId) : null;
    const starredList = Array.isArray(d.starredBy) ? d.starredBy : [];
    const archivedList = Array.isArray(d.archivedBy) ? d.archivedBy : [];
    const trashedList = Array.isArray(d.trashedBy) ? d.trashedBy : [];

    return {
      id: d.id,
      originalName: d.originalName,
      fileType: d.fileType,
      size: d.size,
      ownerId: d.ownerId,
      ownerName: d.ownerName,
      isOwner: (d.ownerId === userId),
      myPermission: (d.ownerId === userId) ? 'owner' : (myAcl?.permission || 'none'),
      expiresAt: (d.ownerId === userId) ? null : (myAcl?.expiresAt || null),
      isStarred: starredList.includes(userId),
      isArchived: archivedList.includes(userId),
      isTrashed: trashedList.includes(userId),
      sharedUsers: (d.wrappedDEKs || []).map(w => ({
        userId: w.userId,
        userName: w.userName,
        permission: w.permission,
        expiresAt: w.expiresAt || null
      })),
      createdAt: d.createdAt,
      updatedAt: d.updatedAt
    };
  });

  const activeDocs = mappedDocs.filter(d => !d.isTrashed && !d.isArchived);
  const totalCount = activeDocs.length;
  const sharedWithMeCount = activeDocs.filter(d => !d.isOwner).length;
  const protectedCount = activeDocs.length;
  const totalBytes = activeDocs.reduce((acc, d) => acc + (d.size || 0), 0);

  res.json({
    documents: mappedDocs,
    metrics: {
      totalDocuments: totalCount,
      sharedWithYou: sharedWithMeCount,
      protectedFiles: protectedCount,
      encryptionRate: '100%',
      totalBytes
    }
  });
});

// Get Document Metadata & User's Wrapped Key
app.get('/api/documents/:id/metadata', pep.authenticate, pep.enforceDocAccess('read'), (req, res) => {
  const doc = req.doc;
  const userAcl = doc.wrappedDEKs.find(w => w.userId === req.user.id);

  res.json({
    document: {
      id: doc.id,
      originalName: doc.originalName,
      fileType: doc.fileType,
      size: doc.size,
      ownerId: doc.ownerId,
      ownerName: doc.ownerName,
      iv: doc.iv,
      authTag: doc.authTag,
      sha512: doc.sha512 || doc.sha256,
      sha256: doc.sha512 || doc.sha256,
      userWrappedDEK: userAcl ? userAcl.wrappedKey : null,
      permission: req.docPermission,
      sharedUsers: doc.wrappedDEKs
    }
  });
});

// Download Raw Encrypted Ciphertext
app.get('/api/documents/:id/download', pep.authenticate, pep.enforceDocAccess('read'), async (req, res) => {
  const doc = req.doc;
  const buffer = await storage.getEncryptedBlob(doc.id);

  if (!buffer) {
    return res.status(404).json({ error: 'Encrypted ciphertext blob missing from vault volume.' });
  }

  const userAcl = doc.wrappedDEKs.find(w => w.userId === req.user.id);

  await auditChain.recordEvent({
    actorId: req.user.id,
    actorName: req.user.fullName,
    actorRole: req.user.role,
    action: 'DOCUMENT_DOWNLOAD',
    targetDocId: doc.id,
    targetDocName: doc.originalName,
    outcome: 'SUCCESS',
    details: {
      permission: req.docPermission,
      bytesTransferred: buffer.length
    }
  });

  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Disposition', `attachment; filename="${doc.id}.enc"`);
  res.setHeader('X-IV', doc.iv);
  res.setHeader('X-Auth-Tag', doc.authTag);
  res.setHeader('X-SHA512', doc.sha512 || doc.sha256 || '');
  res.setHeader('X-SHA256', doc.sha512 || doc.sha256 || '');
  res.setHeader('X-Wrapped-DEK', userAcl ? userAcl.wrappedKey : '');
  res.setHeader('X-Original-Name', encodeURIComponent(doc.originalName));
  res.setHeader('X-Original-Type', doc.fileType);

  res.send(buffer);
});

// Share Document (Append or update recipient's wrapped DEK)
app.post('/api/documents/:id/share', pep.authenticate, pep.enforceDocAccess('share'), async (req, res) => {
  try {
    const { recipientId, permission = 'viewer', wrappedDEK, expiresAt = null } = req.body;

    if (!recipientId || !wrappedDEK) {
      return res.status(400).json({ error: 'Recipient ID and wrapped DEK are required.' });
    }

    const doc = req.doc;

    if (recipientId === doc.ownerId) {
      return res.status(400).json({ error: 'Cannot modify owner permissions in ACL.' });
    }

    const recipient = await db.findUserById(recipientId);
    if (!recipient) {
      return res.status(404).json({ error: 'Recipient user not found.' });
    }

    const existingIndex = doc.wrappedDEKs.findIndex(w => w.userId === recipientId);

    const aclEntry = {
      userId: recipient.id,
      userName: recipient.fullName,
      wrappedKey: wrappedDEK,
      permission: ['editor', 'viewer'].includes(permission) ? permission : 'viewer',
      grantedAt: new Date(),
      expiresAt: expiresAt ? new Date(expiresAt) : null
    };

    if (existingIndex >= 0) {
      doc.wrappedDEKs[existingIndex] = aclEntry;
    } else {
      doc.wrappedDEKs.push(aclEntry);
    }

    // If recipient previously deleted or trashed an older share, restore visibility for this fresh share
    const deletedBy = (doc.deletedBy || []).filter(id => id !== recipientId);
    const trashedBy = (doc.trashedBy || []).filter(id => id !== recipientId);

    const updated = await db.updateDoc(doc.id, {
      wrappedDEKs: doc.wrappedDEKs,
      deletedBy,
      trashedBy
    });

    await auditChain.recordEvent({
      actorId: req.user.id,
      actorName: req.user.fullName,
      actorRole: req.user.role,
      action: 'DOCUMENT_SHARE',
      targetDocId: doc.id,
      targetDocName: doc.originalName,
      outcome: 'SUCCESS',
      details: {
        recipientId: recipient.id,
        recipientName: recipient.fullName,
        permission: aclEntry.permission,
        expiresAt: aclEntry.expiresAt
      }
    });

    res.json({
      message: `Document successfully shared with ${recipient.fullName}.`,
      document: updated
    });
  } catch (err) {
    console.error('Share error:', err);
    res.status(500).json({ error: 'Failed to share document.', details: err.message });
  }
});

// Revoke Document Access
app.post('/api/documents/:id/revoke', pep.authenticate, pep.enforceDocAccess('revoke'), async (req, res) => {
  try {
    const { recipientId } = req.body;
    if (!recipientId) {
      return res.status(400).json({ error: 'Recipient ID is required for revocation.' });
    }

    const doc = req.doc;
    const initialCount = doc.wrappedDEKs.length;
    doc.wrappedDEKs = doc.wrappedDEKs.filter(w => w.userId !== recipientId);

    if (doc.wrappedDEKs.length === initialCount) {
      return res.status(404).json({ error: 'Recipient was not in document ACL.' });
    }

    const updated = await db.updateDoc(doc.id, { wrappedDEKs: doc.wrappedDEKs });

    await auditChain.recordEvent({
      actorId: req.user.id,
      actorName: req.user.fullName,
      actorRole: req.user.role,
      action: 'PERMISSION_REVOKED',
      targetDocId: doc.id,
      targetDocName: doc.originalName,
      outcome: 'SUCCESS',
      details: {
        revokedUserId: recipientId,
        revocationType: 'Standard Server-Side ACL Removal'
      }
    });

    res.json({
      message: 'Access revoked successfully from document ACL.',
      document: updated
    });
  } catch (err) {
    console.error('Revoke error:', err);
    res.status(500).json({ error: 'Failed to revoke access.', details: err.message });
  }
});

// Update Collaborator Permission Level (Owner Only)
app.post('/api/documents/:id/permission', pep.authenticate, pep.enforceDocAccess('revoke'), async (req, res) => {
  try {
    const { recipientId, permission } = req.body;
    if (!recipientId || !['editor', 'viewer'].includes(permission)) {
      return res.status(400).json({ error: 'Valid recipient ID and permission (editor or viewer) are required.' });
    }
    const doc = req.doc;
    const aclIndex = doc.wrappedDEKs.findIndex(w => w.userId === recipientId);
    if (aclIndex === -1) {
      return res.status(404).json({ error: 'Recipient is not in document ACL.' });
    }
    doc.wrappedDEKs[aclIndex].permission = permission;
    const updated = await db.updateDoc(doc.id, { wrappedDEKs: doc.wrappedDEKs });

    await auditChain.recordEvent({
      actorId: req.user.id,
      actorName: req.user.fullName,
      actorRole: req.user.role,
      action: 'PERMISSION_UPDATED',
      targetDocId: doc.id,
      targetDocName: doc.originalName,
      outcome: 'SUCCESS',
      details: {
        recipientId,
        newPermission: permission
      }
    });

    res.json({ message: `Updated permission to ${permission}.`, document: updated });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Toggle Star on Document
app.post('/api/documents/:id/star', pep.authenticate, pep.enforceDocAccess('read'), async (req, res) => {
  try {
    const doc = req.doc;
    const userId = req.user.id;
    let starred = Array.isArray(doc.starredBy) ? [...doc.starredBy] : [];
    const isCurrentlyStarred = starred.includes(userId);

    if (isCurrentlyStarred) {
      starred = starred.filter(id => id !== userId);
    } else {
      starred.push(userId);
    }

    await db.updateDoc(doc.id, { starredBy: starred });
    res.json({
      message: isCurrentlyStarred ? 'Removed from Starred' : 'Added to Starred',
      isStarred: !isCurrentlyStarred
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Toggle Archive on Document (Per-User Workspace Isolation)
app.post('/api/documents/:id/archive', pep.authenticate, pep.enforceDocAccess('personal'), async (req, res) => {
  try {
    const doc = req.doc;
    const userId = req.user.id;
    let archivedBy = Array.isArray(doc.archivedBy) ? [...doc.archivedBy] : [];
    const isCurrentlyArchived = archivedBy.includes(userId);

    if (isCurrentlyArchived) {
      archivedBy = archivedBy.filter(id => id !== userId);
    } else {
      archivedBy.push(userId);
    }

    await db.updateDoc(doc.id, { archivedBy });

    await auditChain.recordEvent({
      actorId: req.user.id,
      actorName: req.user.fullName,
      actorRole: req.user.role,
      action: !isCurrentlyArchived ? 'DOCUMENT_ARCHIVED' : 'DOCUMENT_UNARCHIVED',
      targetDocId: doc.id,
      targetDocName: doc.originalName,
      outcome: 'SUCCESS',
      details: { isArchived: !isCurrentlyArchived, scope: 'Per-User Vault' }
    });

    res.json({
      message: !isCurrentlyArchived ? 'Document moved to your archive.' : 'Document unarchived.',
      isArchived: !isCurrentlyArchived
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Move Document to Trash (Per-User Soft Delete - Does NOT affect other users' copies)
app.post('/api/documents/:id/trash', pep.authenticate, pep.enforceDocAccess('personal'), async (req, res) => {
  try {
    const doc = req.doc;
    const userId = req.user.id;
    const trashedBy = Array.isArray(doc.trashedBy) ? [...doc.trashedBy] : [];
    if (!trashedBy.includes(userId)) trashedBy.push(userId);

    await db.updateDoc(doc.id, { trashedBy });

    await auditChain.recordEvent({
      actorId: req.user.id,
      actorName: req.user.fullName,
      actorRole: req.user.role,
      action: 'DOCUMENT_TRASHED',
      targetDocId: doc.id,
      targetDocName: doc.originalName,
      outcome: 'SUCCESS',
      details: { scope: 'Per-User Trash (Shared recipients unaffected)' }
    });

    res.json({ message: 'Document moved to your Trash.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Restore Document from Trash (Per-User)
app.post('/api/documents/:id/restore', pep.authenticate, pep.enforceDocAccess('personal'), async (req, res) => {
  try {
    const doc = req.doc;
    const userId = req.user.id;
    const trashedBy = (doc.trashedBy || []).filter(id => id !== userId);

    await db.updateDoc(doc.id, { trashedBy });

    await auditChain.recordEvent({
      actorId: req.user.id,
      actorName: req.user.fullName,
      actorRole: req.user.role,
      action: 'DOCUMENT_RESTORED',
      targetDocId: doc.id,
      targetDocName: doc.originalName,
      outcome: 'SUCCESS'
    });

    res.json({ message: 'Document restored from Trash.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Empty All Trashed Documents for Current User
app.post('/api/documents/trash/empty', pep.authenticate, async (req, res) => {
  try {
    const allDocs = await db.getDocuments();
    const userId = req.user.id;
    const trashedDocs = allDocs.filter(d => (d.trashedBy || []).includes(userId));

    for (const doc of trashedDocs) {
      await deleteDocumentForUser(doc, req.user);
    }

    res.json({ message: `Permanently removed ${trashedDocs.length} document(s) from your Trash.` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete Document Permanently for Current User (Owner or Recipient)
app.delete('/api/documents/:id', pep.authenticate, pep.enforceDocAccess('personal'), async (req, res) => {
  try {
    const doc = req.doc;
    await deleteDocumentForUser(doc, req.user);

    res.json({ message: 'Document permanently removed from your workspace.' });
  } catch (err) {
    console.error('Delete error:', err);
    res.status(500).json({ error: 'Failed to delete document.', details: err.message });
  }
});

// ==========================================
// 3. AUDITING & SECURITY CENTER ENDPOINTS
// ==========================================

// Get Audit Logs
app.get('/api/audit/logs', pep.authenticate, async (req, res) => {
  const allLogs = await db.getAuditLogs();
  if (['admin', 'auditor'].includes(req.user.role)) {
    return res.json({ logs: allLogs });
  }
  const userLogs = allLogs.filter(l => l.actorId === req.user.id);
  res.json({ logs: userLogs });
});

// Verify Cryptographic Hash Chain Integrity
app.get('/api/audit/verify', pep.authenticate, async (req, res) => {
  const result = await auditChain.verifyChainIntegrity();

  if (result.valid) {
    await auditChain.recordEvent({
      actorId: req.user.id,
      actorName: req.user.fullName,
      actorRole: req.user.role,
      action: 'AUDIT_INTEGRITY_VERIFIED',
      outcome: 'SUCCESS',
      details: { verifiedBlocks: result.totalBlocks, lastHash: result.lastBlockHash }
    });
  } else {
    await auditChain.recordEvent({
      actorId: req.user.id,
      actorName: req.user.fullName,
      actorRole: req.user.role,
      action: 'AUDIT_TAMPERING_DETECTED',
      outcome: 'DENIED',
      details: { brokenIndex: result.brokenIndex, reason: result.reason }
    });
  }

  res.json(result);
});

// ==========================================
// 4. ADVERSARIAL TESTING ENDPOINTS (PART 3)
// ==========================================

// Storage Exposure Test
app.get('/api/adversarial/inspect-storage/:id', pep.authenticate, async (req, res) => {
  try {
    const inspection = await storage.inspectBlob(req.params.id);
    if (!inspection) {
      return res.status(404).json({ error: 'Blob not found in storage.' });
    }
    res.json(inspection);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Ciphertext Tampering Test
app.post('/api/adversarial/tamper-blob/:id', pep.authenticate, async (req, res) => {
  try {
    const result = await storage.tamperBlobBit(req.params.id);
    await auditChain.recordEvent({
      actorId: req.user.id,
      actorName: req.user.fullName,
      actorRole: req.user.role,
      action: 'ADVERSARIAL_BIT_TAMPER_SIMULATION',
      targetDocId: req.params.id,
      outcome: 'SUCCESS',
      details: result
    });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Audit Tampering Test
app.post('/api/adversarial/tamper-log', pep.authenticate, pep.requireRole('admin'), async (req, res) => {
  try {
    const { index = 1 } = req.body;
    const result = await auditChain.tamperLog(Number(index), 'ALTERED_BY_MALICIOUS_DBA');
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Serve Frontend Static Files (Local / Traditional Node Server)
if (!process.env.VERCEL) {
  const FRONTEND_DIST = path.resolve(__dirname, '..', 'frontend', 'dist');
  if (require('fs').existsSync(FRONTEND_DIST)) {
    app.use(express.static(FRONTEND_DIST));
    app.use((req, res, next) => {
      if (req.method === 'GET' && !req.path.startsWith('/api')) {
        return res.sendFile(path.join(FRONTEND_DIST, 'index.html'));
      }
      next();
    });
  }
}

// Start standalone server only when executed directly (not imported by Vercel Serverless)
if (require.main === module && !process.env.VERCEL) {
  setInterval(() => {
    pruneExpiredAccess().catch(() => {});
  }, 15000);

  ensureInitialized().then(() => {
    app.listen(PORT, () => {
      console.log(`Vaultora Secure Backend listening on port ${PORT}`);
      console.log(`Storage backend: ${db.isUsingMongoose() ? 'MongoDB GridFS (vault_blobs)' : path.resolve(__dirname, '..', 'vault')}`);
    });
  }).catch(err => {
    console.error('Failed to initialize database:', err);
  });
}

module.exports = app;
