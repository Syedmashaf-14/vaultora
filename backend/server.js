require('dotenv').config();
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const db = require('./database');
const auditChain = require('./auditChain');
const storage = require('./storage');
const pep = require('./pep');

const app = express();
const PORT = process.env.PORT || 5000;

// Setup Multer memory storage for incoming encrypted payloads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 100 * 1024 * 1024 } // 100MB
});

// Middleware
app.use(cors({
  origin: ['http://localhost:3000', 'http://127.0.0.1:3000'],
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());

// Enforce security headers on all responses
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});

// ==========================================
// 1. AUTHENTICATION ENDPOINTS (MONGODB)
// ==========================================

// Register User
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, fullName, password, publicKeyPem, role = 'user' } = req.body;

    if (!username || !email || !password || !publicKeyPem) {
      return res.status(400).json({ error: 'Username, email, password, and RSA public key are required.' });
    }

    const existingUser = await db.findUserByUsername(username);
    if (existingUser) {
      return res.status(409).json({ error: 'Username is already registered.' });
    }
    const existingEmail = await db.findUserByEmail(email);
    if (existingEmail) {
      return res.status(409).json({ error: 'Email address is already in use.' });
    }

    const argon2Hash = await pep.hashPassword(password);
    const userId = `usr_${uuidv4().substring(0, 8)}`;

    const newUser = {
      id: userId,
      username: username.toLowerCase().trim(),
      email: email.toLowerCase().trim(),
      fullName: fullName || username,
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
    res.cookie('jwt', token, {
      httpOnly: true,
      secure: false,
      sameSite: 'strict',
      maxAge: 2 * 60 * 60 * 1000 // 2 hours
    });

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
    res.cookie('jwt', token, {
      httpOnly: true,
      secure: false,
      sameSite: 'strict',
      maxAge: 2 * 60 * 60 * 1000
    });

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
  res.clearCookie('jwt');
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

    // Save pure ciphertext in physical vault
    storage.saveEncryptedBlob(docId, req.file.buffer);

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

// List Documents Accessible to Current User
app.get('/api/documents', pep.authenticate, async (req, res) => {
  const allDocs = await db.getDocuments();
  const userId = req.user.id;

  // Filter documents where user is owner OR user exists in wrappedDEKs ACL
  const accessibleDocs = allDocs.filter(d => {
    if (d.ownerId === userId) return true;
    return d.wrappedDEKs && d.wrappedDEKs.some(w => w.userId === userId);
  });

  const activeDocs = accessibleDocs.filter(d => !d.isTrashed && !d.isArchived);
  const totalCount = activeDocs.length;
  const sharedWithMeCount = activeDocs.filter(d => d.ownerId !== userId).length;
  const protectedCount = activeDocs.length;
  const totalBytes = activeDocs.reduce((acc, d) => acc + (d.size || 0), 0);

  res.json({
    documents: accessibleDocs.map(d => {
      const myAcl = d.wrappedDEKs ? d.wrappedDEKs.find(w => w.userId === userId) : null;
      const starredList = Array.isArray(d.starredBy) ? d.starredBy : [];
      return {
        id: d.id,
        originalName: d.originalName,
        fileType: d.fileType,
        size: d.size,
        ownerId: d.ownerId,
        ownerName: d.ownerName,
        isOwner: (d.ownerId === userId),
        myPermission: (d.ownerId === userId) ? 'owner' : (myAcl?.permission || 'none'),
        expiresAt: myAcl?.expiresAt || null,
        isStarred: starredList.includes(userId),
        isArchived: !!d.isArchived,
        isTrashed: !!d.isTrashed,
        trashedAt: d.trashedAt || null,
        sharedUsers: (d.wrappedDEKs || []).map(w => ({
          userId: w.userId,
          userName: w.userName,
          permission: w.permission
        })),
        createdAt: d.createdAt,
        updatedAt: d.updatedAt
      };
    }),
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
  const buffer = storage.getEncryptedBlob(doc.id);

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

    const recipient = await db.findUserById(recipientId);
    if (!recipient) {
      return res.status(404).json({ error: 'Recipient user not found.' });
    }

    const doc = req.doc;
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

    const updated = await db.updateDoc(doc.id, { wrappedDEKs: doc.wrappedDEKs });

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

// Toggle Archive on Document
app.post('/api/documents/:id/archive', pep.authenticate, pep.enforceDocAccess('write'), async (req, res) => {
  try {
    const doc = req.doc;
    const newArchivedState = !doc.isArchived;
    await db.updateDoc(doc.id, { isArchived: newArchivedState });

    await auditChain.recordEvent({
      actorId: req.user.id,
      actorName: req.user.fullName,
      actorRole: req.user.role,
      action: newArchivedState ? 'DOCUMENT_ARCHIVED' : 'DOCUMENT_UNARCHIVED',
      targetDocId: doc.id,
      targetDocName: doc.originalName,
      outcome: 'SUCCESS',
      details: { isArchived: newArchivedState }
    });

    res.json({
      message: newArchivedState ? 'Document moved to archive.' : 'Document unarchived.',
      isArchived: newArchivedState
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Move Document to Trash (Soft Delete)
app.post('/api/documents/:id/trash', pep.authenticate, pep.enforceDocAccess('delete'), async (req, res) => {
  try {
    const doc = req.doc;
    await db.updateDoc(doc.id, { isTrashed: true, trashedAt: new Date() });

    await auditChain.recordEvent({
      actorId: req.user.id,
      actorName: req.user.fullName,
      actorRole: req.user.role,
      action: 'DOCUMENT_TRASHED',
      targetDocId: doc.id,
      targetDocName: doc.originalName,
      outcome: 'SUCCESS'
    });

    res.json({ message: 'Document moved to Trash.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Restore Document from Trash
app.post('/api/documents/:id/restore', pep.authenticate, pep.enforceDocAccess('delete'), async (req, res) => {
  try {
    const doc = req.doc;
    await db.updateDoc(doc.id, { isTrashed: false, trashedAt: null });

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

// Empty All Trashed Documents
app.post('/api/documents/trash/empty', pep.authenticate, async (req, res) => {
  try {
    const allDocs = await db.getDocuments();
    const trashedDocs = allDocs.filter(d => d.ownerId === req.user.id && d.isTrashed);

    for (const doc of trashedDocs) {
      storage.deleteEncryptedBlob(doc.id);
      await db.deleteDoc(doc.id);
      await auditChain.recordEvent({
        actorId: req.user.id,
        actorName: req.user.fullName,
        actorRole: req.user.role,
        action: 'DOCUMENT_PURGED',
        targetDocId: doc.id,
        targetDocName: doc.originalName,
        outcome: 'SUCCESS',
        details: { permanentPurge: true }
      });
    }

    res.json({ message: `Purged ${trashedDocs.length} documents from Trash.` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete Document (Permanent)
app.delete('/api/documents/:id', pep.authenticate, pep.enforceDocAccess('delete'), async (req, res) => {
  try {
    const doc = req.doc;

    storage.deleteEncryptedBlob(doc.id);
    await db.deleteDoc(doc.id);

    await auditChain.recordEvent({
      actorId: req.user.id,
      actorName: req.user.fullName,
      actorRole: req.user.role,
      action: 'DOCUMENT_DELETED',
      targetDocId: doc.id,
      targetDocName: doc.originalName,
      outcome: 'SUCCESS',
      details: {
        sizeBytes: doc.size
      }
    });

    res.json({ message: 'Document and encrypted vault blob deleted permanently.' });
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
app.get('/api/adversarial/inspect-storage/:id', pep.authenticate, (req, res) => {
  const inspection = storage.inspectBlob(req.params.id);
  if (!inspection) {
    return res.status(404).json({ error: 'Blob not found in storage.' });
  }
  res.json(inspection);
});

// Ciphertext Tampering Test
app.post('/api/adversarial/tamper-blob/:id', pep.authenticate, async (req, res) => {
  try {
    const result = storage.tamperBlobBit(req.params.id);
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

// Serve Frontend Static Files
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

// Start Server and Connect DB
const seedDefaultUsers = require('./seedData');

db.connect().then(async () => {
  await seedDefaultUsers();
  app.listen(PORT, () => {
    console.log(`Vaultora Secure Backend listening on port ${PORT}`);
    console.log(`Storage volume mounted at: ${path.resolve(__dirname, '..', 'vault')}`);
  });
}).catch(err => {
  console.error('Failed to initialize database:', err);
});
