const argon2 = require('argon2');
const jwt = require('jsonwebtoken');
const db = require('./database');
const auditChain = require('./auditChain');

const JWT_SECRET = process.env.JWT_SECRET || 'vaultora_cryptographic_jwt_hmac_secret_2026_fast';

const pep = {
  // Argon2id Password Hashing
  async hashPassword(plaintext) {
    return await argon2.hash(plaintext, {
      type: argon2.argon2id,
      memoryCost: 65536, // 64 MB
      timeCost: 3,       // 3 iterations
      parallelism: 4     // 4 threads
    });
  },

  async verifyPassword(hash, plaintext) {
    try {
      return await argon2.verify(hash, plaintext);
    } catch {
      return false;
    }
  },

  // JWT Token Management
  generateToken(user) {
    return jwt.sign(
      {
        id: user.id,
        username: user.username,
        role: user.role,
        fullName: user.fullName
      },
      JWT_SECRET,
      { expiresIn: '2h' }
    );
  },

  // Auth Middleware
  async authenticate(req, res, next) {
    let token = req.cookies?.jwt;
    if (!token && req.headers.authorization) {
      const parts = req.headers.authorization.split(' ');
      if (parts.length === 2 && parts[0] === 'Bearer') {
        token = parts[1];
      }
    }

    if (!token) {
      return res.status(401).json({ error: 'Authentication required. No session token provided.' });
    }

    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const user = await db.findUserById(decoded.id);
      if (!user) {
        return res.status(401).json({ error: 'User account not found or has been revoked.' });
      }
      req.user = user;
      next();
    } catch (err) {
      return res.status(401).json({ error: 'Invalid or expired session token.', details: err.message });
    }
  },

  // RBAC Middleware
  requireRole(...allowedRoles) {
    return async (req, res, next) => {
      if (!req.user || !allowedRoles.includes(req.user.role)) {
        await auditChain.recordEvent({
          actorId: req.user?.id,
          actorName: req.user?.fullName,
          actorRole: req.user?.role,
          action: 'PRIVILEGE_MISUSE_BLOCKED',
          outcome: 'DENIED',
          details: {
            attemptedEndpoint: req.originalUrl,
            requiredRoles: allowedRoles,
            userRole: req.user?.role
          }
        });
        return res.status(403).json({
          error: `Access Denied: Requires one of [${allowedRoles.join(', ')}] roles.`
        });
      }
      next();
    };
  },

  // DAC (Discretionary Access Control) Policy Enforcement Point
  enforceDocAccess(requiredPermission = 'read') {
    return async (req, res, next) => {
      const docId = req.params.id || req.body.docId;
      if (!docId) {
        return res.status(400).json({ error: 'Document ID is required.' });
      }

      const doc = await db.findDocById(docId);
      if (!doc) {
        return res.status(404).json({ error: 'Document not found.' });
      }

      const userId = req.user.id;
      const deletedBy = Array.isArray(doc.deletedBy) ? doc.deletedBy : [];
      if (deletedBy.includes(userId)) {
        return res.status(404).json({ error: 'Document has been removed from your workspace.' });
      }

      const isOwner = (doc.ownerId === userId);

      // Check if user is in Document ACL (wrappedDEKs array)
      const aclEntry = (doc.wrappedDEKs || []).find(w => w.userId === userId);

      // Check temporal expiration if user has an ACL entry
      if (!isOwner && aclEntry && aclEntry.expiresAt) {
        const now = new Date();
        const exp = new Date(aclEntry.expiresAt);
        if (now > exp) {
          // Auto-remove expired entry immediately (not moved to trash)
          const remainingDEKs = (doc.wrappedDEKs || []).filter(w => w.userId !== userId);
          await db.updateDoc(doc.id, {
            wrappedDEKs: remainingDEKs,
            starredBy: (doc.starredBy || []).filter(id => id !== userId),
            archivedBy: (doc.archivedBy || []).filter(id => id !== userId),
            trashedBy: (doc.trashedBy || []).filter(id => id !== userId)
          });

          await auditChain.recordEvent({
            actorId: req.user.id,
            actorName: req.user.fullName,
            actorRole: req.user.role,
            action: 'TEMPORARY_ACCESS_EXPIRED',
            targetDocId: doc.id,
            targetDocName: doc.originalName,
            outcome: 'DENIED',
            details: { expiresAt: aclEntry.expiresAt, action: 'Auto-deleted expired access' }
          });
          return res.status(403).json({
            error: 'Temporary access expired: This document has been automatically removed.',
            expiredAt: aclEntry.expiresAt
          });
        }
      }

      // Personal workspace operations (star, archive, trash, restore, delete-self) allowed for any authorized holder
      if (requiredPermission === 'personal') {
        if (isOwner || aclEntry) {
          req.doc = doc;
          req.docPermission = isOwner ? 'owner' : aclEntry.permission;
          req.userWrappedDEK = aclEntry ? aclEntry.wrappedKey : null;
          return next();
        }
      }

      // Owner has full rights
      if (isOwner) {
        req.doc = doc;
        req.docPermission = 'owner';
        return next();
      }

      // Revoke and Owner-level mutations are strictly Owner-Only
      if (['delete', 'revoke', 're-encrypt'].includes(requiredPermission)) {
        await auditChain.recordEvent({
          actorId: req.user.id,
          actorName: req.user.fullName,
          actorRole: req.user.role,
          action: 'UNAUTHORIZED_DOC_MUTATION',
          targetDocId: doc.id,
          targetDocName: doc.originalName,
          outcome: 'DENIED',
          details: { requiredPermission, isOwner: false }
        });
        return res.status(403).json({
          error: `Only the document owner can perform '${requiredPermission}' operations.`
        });
      }

      // Check sharing permissions
      if (aclEntry) {
        const userPerm = aclEntry.permission; // 'viewer' or 'editor'

        if (requiredPermission === 'read') {
          req.doc = doc;
          req.docPermission = userPerm;
          req.userWrappedDEK = aclEntry.wrappedKey;
          return next();
        }

        if (requiredPermission === 'write' || requiredPermission === 'share') {
          if (userPerm === 'editor') {
            req.doc = doc;
            req.docPermission = 'editor';
            req.userWrappedDEK = aclEntry.wrappedKey;
            return next();
          } else {
            const actionLabel = requiredPermission === 'share' ? 'share or delegate access to other users' : requiredPermission;
            await auditChain.recordEvent({
              actorId: req.user.id,
              actorName: req.user.fullName,
              actorRole: req.user.role,
              action: 'INSUFFICIENT_DAC_PERMISSION',
              targetDocId: doc.id,
              targetDocName: doc.originalName,
              outcome: 'DENIED',
              details: { requiredPermission, userPerm }
            });
            return res.status(403).json({
              error: `Access Denied (DAC Policy): You have '${userPerm}' privilege (Read & Decrypt only). You are not authorized to ${actionLabel}.`
            });
          }
        }
      }

      // If user is not the owner and not in ACL
      await auditChain.recordEvent({
        actorId: req.user.id,
        actorName: req.user.fullName,
        actorRole: req.user.role,
        action: 'UNAUTHORIZED_ACCESS_ATTEMPT',
        targetDocId: doc.id,
        targetDocName: doc.originalName,
        outcome: 'DENIED',
        details: {
          note: 'IDOR or unauthorized access attempt. User not in ACL.',
          attemptedPermission: requiredPermission
        }
      });

      return res.status(403).json({
        error: 'Access Denied: You do not have permission to access this document.'
      });
    };
  }
};

module.exports = pep;
