require('dotenv').config();
const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');

const DATA_DIR = process.env.VERCEL
  ? '/tmp/vaultora_data'
  : path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const DOCS_FILE = path.join(DATA_DIR, 'documents.json');
const AUDIT_FILE = path.join(DATA_DIR, 'audit_logs.json');

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

function readJSON(filePath, defaultValue = []) {
  try {
    ensureDataDir();
    if (!fs.existsSync(filePath)) {
      fs.writeFileSync(filePath, JSON.stringify(defaultValue, null, 2), 'utf-8');
      return defaultValue;
    }
    return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
  } catch {
    return defaultValue;
  }
}

function writeJSON(filePath, data) {
  ensureDataDir();
  const tmp = `${filePath}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf-8');
  fs.renameSync(tmp, filePath);
}

// Mongoose Schemas
const UserSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  username: { type: String, required: true, unique: true, lowercase: true, trim: true },
  fullName: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  role: { type: String, enum: ['admin', 'user', 'auditor'], default: 'user' },
  argon2Hash: { type: String, required: true },
  publicKeyPem: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const DocumentSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  originalName: { type: String, required: true },
  fileType: { type: String, default: 'bin' },
  size: { type: Number, required: true },
  ownerId: { type: String, required: true },
  ownerName: { type: String, required: true },
  iv: { type: String, required: true },
  authTag: { type: String, required: true },
  sha512: { type: String },
  sha256: { type: String },
  storagePath: { type: String, required: true },
  wrappedDEKs: [
    {
      userId: { type: String, required: true },
      userName: { type: String, required: true },
      wrappedKey: { type: String, required: true },
      permission: { type: String, enum: ['owner', 'editor', 'viewer'], default: 'viewer' },
      grantedAt: { type: Date, default: Date.now },
      expiresAt: { type: Date, default: null }
    }
  ],
  archivedBy: [{ type: String }],
  trashedBy: [{ type: String }],
  deletedBy: [{ type: String }],
  starredBy: [{ type: String }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const AuditLogSchema = new mongoose.Schema({
  index: { type: Number, required: true, unique: true },
  timestamp: { type: Date, default: Date.now },
  actorId: { type: String, required: true },
  actorName: { type: String, required: true },
  actorRole: { type: String, required: true },
  action: { type: String, required: true },
  targetDocId: { type: String, default: null },
  targetDocName: { type: String, default: null },
  outcome: { type: String, enum: ['SUCCESS', 'DENIED', 'FAILED'], required: true },
  details: { type: mongoose.Schema.Types.Mixed, default: {} },
  prevHash: { type: String, required: true },
  currHash: { type: String, required: true }
});

let UserModel;
let DocumentModel;
let AuditLogModel;
let usingMongoose = false;
let connectPromise = null;

function registerModels() {
  UserModel = mongoose.models.User || mongoose.model('User', UserSchema);
  DocumentModel = mongoose.models.Document || mongoose.model('Document', DocumentSchema);
  AuditLogModel = mongoose.models.AuditLog || mongoose.model('AuditLog', AuditLogSchema);
}

async function connectDB() {
  if (usingMongoose && mongoose.connection.readyState === 1) {
    registerModels();
    return;
  }

  if (connectPromise) {
    return connectPromise;
  }

  connectPromise = (async () => {
    const envUri = process.env.MONGODB_URI?.trim();
    if (envUri) {
      try {
        console.log(`Attempting connection to MongoDB Cluster...`);
        await mongoose.connect(envUri, { serverSelectionTimeoutMS: 5000 });
        registerModels();
        usingMongoose = true;
        console.log('✓ Successfully connected to MongoDB Cluster.');
        return;
      } catch (err) {
        console.warn('Could not connect to external MONGODB_URI:', err.message);
        if (process.env.VERCEL) {
          throw new Error(`MongoDB connection failed on Vercel: ${err.message}`);
        }
      }
    } else if (process.env.VERCEL) {
      throw new Error('MONGODB_URI environment variable is required when running on Vercel.');
    }

    // Try local MongoDB on 27017 (local dev only)
    try {
      await mongoose.connect('mongodb://127.0.0.1:27017/vaultora', { serverSelectionTimeoutMS: 1500 });
      registerModels();
      usingMongoose = true;
      console.log('✓ Connected to local MongoDB instance on port 27017.');
      return;
    } catch {
      console.log('ℹ Local MongoDB daemon not running. Active in high-performance local document store mode.');
      usingMongoose = false;
    }
  })();

  try {
    await connectPromise;
  } finally {
    connectPromise = null;
  }
}

const db = {
  connect: connectDB,
  isUsingMongoose() {
    return usingMongoose && mongoose.connection.readyState === 1 && !!mongoose.connection.db;
  },
  getMongoDb() {
    return mongoose.connection.db;
  },

  // Users
  async getUsers() {
    if (usingMongoose) return await UserModel.find({}).lean();
    return readJSON(USERS_FILE, []);
  },
  async findUserById(id) {
    if (usingMongoose) return await UserModel.findOne({ id }).lean();
    const users = readJSON(USERS_FILE, []);
    return users.find(u => u.id === id) || null;
  },
  async findUserByUsername(username) {
    if (usingMongoose) return await UserModel.findOne({ username: username.toLowerCase().trim() }).lean();
    const users = readJSON(USERS_FILE, []);
    return users.find(u => u.username.toLowerCase() === username.toLowerCase().trim()) || null;
  },
  async findUserByEmail(email) {
    if (usingMongoose) return await UserModel.findOne({ email: email.toLowerCase().trim() }).lean();
    const users = readJSON(USERS_FILE, []);
    return users.find(u => u.email.toLowerCase() === email.toLowerCase().trim()) || null;
  },
  async createUser(userData) {
    if (usingMongoose) {
      const user = new UserModel(userData);
      await user.save();
      return user.toObject();
    }
    const users = readJSON(USERS_FILE, []);
    users.push(userData);
    writeJSON(USERS_FILE, users);
    return userData;
  },
  async updateUser(id, updates) {
    if (usingMongoose) {
      return await UserModel.findOneAndUpdate({ id }, { ...updates, updatedAt: new Date() }, { new: true }).lean();
    }
    const users = readJSON(USERS_FILE, []);
    const idx = users.findIndex(u => u.id === id);
    if (idx === -1) return null;
    users[idx] = { ...users[idx], ...updates, updatedAt: new Date().toISOString() };
    writeJSON(USERS_FILE, users);
    return users[idx];
  },

  // Documents
  async getDocuments() {
    if (usingMongoose) return await DocumentModel.find({}).lean();
    return readJSON(DOCS_FILE, []);
  },
  async findDocById(id) {
    if (usingMongoose) return await DocumentModel.findOne({ id }).lean();
    const docs = readJSON(DOCS_FILE, []);
    return docs.find(d => d.id === id) || null;
  },
  async createDoc(docData) {
    if (usingMongoose) {
      const doc = new DocumentModel(docData);
      await doc.save();
      return doc.toObject();
    }
    const docs = readJSON(DOCS_FILE, []);
    docs.push(docData);
    writeJSON(DOCS_FILE, docs);
    return docData;
  },
  async updateDoc(id, updates) {
    if (usingMongoose) {
      return await DocumentModel.findOneAndUpdate({ id }, { ...updates, updatedAt: new Date() }, { new: true }).lean();
    }
    const docs = readJSON(DOCS_FILE, []);
    const idx = docs.findIndex(d => d.id === id);
    if (idx === -1) return null;
    docs[idx] = { ...docs[idx], ...updates, updatedAt: new Date().toISOString() };
    writeJSON(DOCS_FILE, docs);
    return docs[idx];
  },
  async deleteDoc(id) {
    if (usingMongoose) {
      const result = await DocumentModel.deleteOne({ id });
      return result.deletedCount > 0;
    }
    const docs = readJSON(DOCS_FILE, []);
    const filtered = docs.filter(d => d.id !== id);
    writeJSON(DOCS_FILE, filtered);
    return docs.length !== filtered.length;
  },

  // Audit Logs
  async getAuditLogs() {
    if (usingMongoose) return await AuditLogModel.find({}).sort({ index: 1 }).lean();
    return readJSON(AUDIT_FILE, []);
  },
  async appendAuditLog(entry) {
    if (usingMongoose) {
      const log = new AuditLogModel(entry);
      await log.save();
      return log.toObject();
    }
    const logs = readJSON(AUDIT_FILE, []);
    logs.push(entry);
    writeJSON(AUDIT_FILE, logs);
    return entry;
  },
  async overwriteAuditLogs(logs) {
    if (usingMongoose) {
      await AuditLogModel.deleteMany({});
      if (logs.length > 0) await AuditLogModel.insertMany(logs);
      return;
    }
    writeJSON(AUDIT_FILE, logs);
  }
};

module.exports = db;
