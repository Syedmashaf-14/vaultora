import React, { useState, useEffect } from 'react';
import {
  Shield,
  FileText,
  Users,
  Lock,
  HardDrive,
  Search,
  Bell,
  MoreVertical,
  Plus,
  CheckCircle2,
  AlertTriangle,
  Star,
  Clock,
  Archive,
  Trash2,
  Share2,
  Download,
  Key,
  ShieldCheck,
  RefreshCw,
  Eye,
  FileCode,
  FileArchive,
  LogOut,
  User,
  Mail,
  ChevronRight,
  X,
  AlertCircle,
  Database
} from 'lucide-react';

import {
  generateUserKeyPair,
  encryptAndStorePrivateKey,
  loadAndDecryptPrivateKey,
  encryptDocument,
  decryptDocument,
  wrapDEKForRecipient,
  importPublicKey,
  bufferToBase64,
  base64ToBuffer
} from './cryptoEngine';
import demoKeys from './demoKeys.json';

export default function App() {
  // Navigation & View State
  const [activeTab, setActiveTab] = useState('overview'); // 'overview', 'mydocs', 'shared'
  const [searchQuery, setSearchQuery] = useState('');

  // Authentication State
  const [currentUser, setCurrentUser] = useState(null);
  const [userPrivateKey, setUserPrivateKey] = useState(null); // Volatile memory only!
  const [authMode, setAuthMode] = useState('login'); // 'login' or 'register'
  const [authForm, setAuthForm] = useState({
    username: '',
    fullName: '',
    email: '',
    password: '',
    role: 'user' // 'admin', 'user', 'auditor'
  });
  const [cryptoStatus, setCryptoStatus] = useState('');
  const [authError, setAuthError] = useState('');

  // Workspace Data State
  const [documents, setDocuments] = useState([]);
  const [metrics, setMetrics] = useState({
    totalDocuments: 0,
    sharedWithYou: 0,
    protectedFiles: 0,
    encryptionRate: '100%',
    totalBytes: 0
  });
  const [allUsers, setAllUsers] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [notification, setNotification] = useState(null);

  // Modals
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [showShareModal, setShowShareModal] = useState(false);
  const [selectedDoc, setSelectedDoc] = useState(null);
  const [showSecurityCenter, setShowSecurityCenter] = useState(false);
  const [auditVerification, setAuditVerification] = useState(null);
  const [storageInspection, setStorageInspection] = useState(null);
  const [activeMenuDocId, setActiveMenuDocId] = useState(null);

  // Upload State
  const [uploadFile, setUploadFile] = useState(null);
  const [uploadProgress, setUploadProgress] = useState(null);

  // Share State
  const [shareRecipientId, setShareRecipientId] = useState('');
  const [sharePermission, setSharePermission] = useState('viewer');
  const [shareExpiryHours, setShareExpiryHours] = useState('');

  const showToast = (message, type = 'info') => {
    setNotification({ message, type });
    setTimeout(() => setNotification(null), 5000);
  };

  // Initial Auth Check
  useEffect(() => {
    checkSession();
  }, []);

  const checkSession = async () => {
    try {
      setLoading(true);
      const res = await fetch('/api/auth/me');
      if (res.ok) {
        const data = await res.json();
        setCurrentUser(data.user);

        // Ensure demo keys are ready in localStorage for demo users
        if (demoKeys && demoKeys[data.user.id]) {
          const stored = localStorage.getItem(`vaultora_key_${data.user.id}`);
          if (!stored || JSON.parse(stored).publicKeyPem !== demoKeys[data.user.id].publicKeyPem) {
            localStorage.setItem(`vaultora_key_${data.user.id}`, JSON.stringify(demoKeys[data.user.id]));
          }
          try {
            const privKey = await loadAndDecryptPrivateKey('Password123!', data.user.id);
            setUserPrivateKey(privKey);
          } catch (e) {
            console.warn('Auto-unlock private key deferred:', e);
          }
        }

        await loadDashboardData();
      } else {
        setCurrentUser(null);
      }
    } catch {
      setCurrentUser(null);
    } finally {
      setLoading(false);
    }
  };

  // 1. Sign Up Handler (Generates RSA Keypair + PBKDF2 KEK -> MongoDB)
  const handleRegister = async (e) => {
    e.preventDefault();
    setAuthError('');
    const { username, fullName, email, password, role } = authForm;

    if (!username || !fullName || !email || !password) {
      setAuthError('Please fill in all required fields.');
      return;
    }

    try {
      setCryptoStatus('1/3: Generating 2048-bit RSA-OAEP Keypair via Web Crypto API...');
      const keyPair = await generateUserKeyPair();

      setCryptoStatus('2/3: Deriving PBKDF2 KEK (600,000 iterations) to protect private key...');
      // Key will be stored using user.id once assigned by backend
      const tempId = `reg_${username.toLowerCase()}`;
      await encryptAndStorePrivateKey(keyPair.privateKey, password, tempId);

      setCryptoStatus('3/3: Storing profile & Argon2id hash in MongoDB Cluster...');
      const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username,
          fullName,
          email,
          password,
          role,
          publicKeyPem: keyPair.publicKeyPem
        })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Registration failed');
      }

      // Re-map local private key under the assigned user id
      const keyRecord = await encryptAndStorePrivateKey(keyPair.privateKey, password, data.user.id);
      keyRecord.publicKeyPem = keyPair.publicKeyPem;
      localStorage.setItem(`vaultora_key_${data.user.id}`, JSON.stringify(keyRecord));
      setUserPrivateKey(keyPair.privateKey);
      setCurrentUser(data.user);

      showToast(`Welcome ${data.user.fullName}! Account created in MongoDB with role: ${data.user.role.toUpperCase()}`, 'success');
      await loadDashboardData();
    } catch (err) {
      console.error('Registration error:', err);
      setAuthError(err.message);
    } finally {
      setCryptoStatus('');
    }
  };

  // 2. Sign In Handler (Argon2id verification via MongoDB + Unlock Local RSA Private Key)
  const handleLogin = async (e) => {
    e.preventDefault();
    setAuthError('');
    const { username, password } = authForm;

    if (!username || !password) {
      setAuthError('Username and password are required.');
      return;
    }

    try {
      setCryptoStatus('Authenticating credentials via MongoDB Argon2id...');
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Invalid credentials');
      }

      setCryptoStatus('Unlocking local RSA Private Key from storage...');

      // Seed demo key if this is a pre-seeded account
      if (demoKeys && demoKeys[data.user.id]) {
        const stored = localStorage.getItem(`vaultora_key_${data.user.id}`);
        if (!stored || JSON.parse(stored).publicKeyPem !== demoKeys[data.user.id].publicKeyPem) {
          localStorage.setItem(`vaultora_key_${data.user.id}`, JSON.stringify(demoKeys[data.user.id]));
        }
      }

      try {
        const privKey = await loadAndDecryptPrivateKey(password, data.user.id);
        setUserPrivateKey(privKey);

        // Verify if local key matches user's public key in MongoDB
        const stored = localStorage.getItem(`vaultora_key_${data.user.id}`);
        if (stored) {
          const rec = JSON.parse(stored);
          if (rec.publicKeyPem && rec.publicKeyPem !== data.user.publicKeyPem) {
            await fetch('/api/auth/sync-key', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ publicKeyPem: rec.publicKeyPem })
            });
            data.user.publicKeyPem = rec.publicKeyPem;
          }
        }
      } catch {
        console.warn('Generating fresh keypair and synchronizing with MongoDB...');
        const keyPair = await generateUserKeyPair();
        const keyRecord = await encryptAndStorePrivateKey(keyPair.privateKey, password, data.user.id);
        keyRecord.publicKeyPem = keyPair.publicKeyPem;
        localStorage.setItem(`vaultora_key_${data.user.id}`, JSON.stringify(keyRecord));
        setUserPrivateKey(keyPair.privateKey);

        await fetch('/api/auth/sync-key', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ publicKeyPem: keyPair.publicKeyPem })
        });
        data.user.publicKeyPem = keyPair.publicKeyPem;
      }

      setCurrentUser(data.user);
      showToast(`Logged in successfully as ${data.user.fullName} (${data.user.role})`, 'success');
      await loadDashboardData();
    } catch (err) {
      console.error('Login error:', err);
      setAuthError(err.message);
    } finally {
      setCryptoStatus('');
    }
  };

  // 3. Logout
  const handleLogout = async () => {
    try {
      await fetch('/api/auth/logout', { method: 'POST' });
      setCurrentUser(null);
      setUserPrivateKey(null);
      setDocuments([]);
      setAuditLogs([]);
      setAuthForm({ username: '', fullName: '', email: '', password: '', role: 'user' });
      showToast('Logged out securely. Session destroyed.', 'info');
    } catch (err) {
      console.error('Logout error:', err);
    }
  };

  // Load Dashboard Data from MongoDB
  const loadDashboardData = async () => {
    try {
      const docRes = await fetch('/api/documents');
      if (docRes.ok) {
        const docData = await docRes.json();
        setDocuments(docData.documents || []);
        if (docData.metrics) {
          setMetrics(docData.metrics);
        }
      }

      const usersRes = await fetch('/api/auth/users');
      if (usersRes.ok) {
        const uData = await usersRes.json();
        setAllUsers(uData.users || []);
        const otherUsers = (uData.users || []).filter(u => u.id !== currentUser?.id);
        if (otherUsers.length > 0 && !shareRecipientId) {
          setShareRecipientId(otherUsers[0].id);
        }
      }

      const auditRes = await fetch('/api/audit/logs');
      if (auditRes.ok) {
        const aData = await auditRes.json();
        setAuditLogs(aData.logs || []);
      }
    } catch (err) {
      console.error('Error loading dashboard data:', err);
    }
  };

  // 4. File Upload (Client AES-256-GCM + Public Key Wrap -> MongoDB + Vault)
  const handleFileUpload = async (e) => {
    e.preventDefault();
    if (!uploadFile) {
      showToast('Please select a file to encrypt and upload.', 'error');
      return;
    }

    try {
      setUploadProgress('Reading file into volatile memory...');
      const fileBuffer = await uploadFile.arrayBuffer();

      setUploadProgress('Generating 256-bit AES-GCM DEK & 12-byte IV...');
      // Ensure we use the exact public key matching the active private key
      let ownerPem = currentUser.publicKeyPem;
      const storedKey = localStorage.getItem(`vaultora_key_${currentUser.id}`);
      if (storedKey) {
        try {
          const parsed = JSON.parse(storedKey);
          if (parsed.publicKeyPem) ownerPem = parsed.publicKeyPem;
        } catch {}
      }

      const pubKey = await importPublicKey(ownerPem);

      setUploadProgress('Encrypting file locally via AES-256-GCM...');
      const encResult = await encryptDocument(fileBuffer, pubKey);

      setUploadProgress('Wrapping DEK with your RSA-OAEP public key...');
      const formData = new FormData();
      formData.append('file', encResult.encryptedBlob, `${uploadFile.name}.enc`);
      formData.append('originalName', uploadFile.name);
      formData.append('fileType', uploadFile.name.split('.').pop() || 'bin');
      formData.append('iv', encResult.ivBase64);
      formData.append('authTag', encResult.authTagBase64);
      formData.append('sha512', encResult.sha512Hex);
      formData.append('sha256', encResult.sha512Hex);
      formData.append('wrappedDEK', encResult.wrappedDEKBase64);

      setUploadProgress('Storing metadata in MongoDB and ciphertext to /vault/...');
      const res = await fetch('/api/documents/upload', {
        method: 'POST',
        body: formData
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.error || 'Server upload failed');
      }

      showToast(`"${uploadFile.name}" encrypted locally and saved!`, 'success');
      setShowUploadModal(false);
      setUploadFile(null);
      setUploadProgress(null);
      await loadDashboardData();
    } catch (err) {
      console.error('Upload error:', err);
      showToast(`Encryption / Upload error: ${err.message}`, 'error');
      setUploadProgress(null);
    }
  };

  // 5. Download & Decrypt
  const handleDownloadAndDecrypt = async (doc) => {
    try {
      showToast(`Fetching ciphertext for "${doc.originalName}"...`, 'info');

      const metaRes = await fetch(`/api/documents/${doc.id}/metadata`);
      if (!metaRes.ok) {
        const errData = await metaRes.json();
        throw new Error(errData.error || 'Access Denied / IDOR Violation');
      }
      const { document: meta } = await metaRes.json();

      if (!meta.userWrappedDEK) {
        throw new Error('No wrapped DEK found for your account in the document Access Control List (ACL).');
      }

      const dlRes = await fetch(`/api/documents/${doc.id}/download`);
      if (!dlRes.ok) {
        const err = await dlRes.json();
        throw new Error(err.error || 'Download failed');
      }

      const encryptedBuffer = await dlRes.arrayBuffer();

      showToast('Unwrapping DEK and decrypting via AES-256-GCM...', 'info');

      let privKey = userPrivateKey;
      if (!privKey) {
        const pass = prompt('Enter your password to unlock your RSA private key:');
        if (!pass) return;
        privKey = await loadAndDecryptPrivateKey(pass, currentUser.id);
        setUserPrivateKey(privKey);
      }

      let decryptedBuffer;
      let verifiedSha512;
      try {
        const result = await decryptDocument(
          encryptedBuffer,
          meta.iv,
          meta.authTag,
          meta.sha512 || meta.sha256,
          meta.userWrappedDEK,
          privKey
        );
        decryptedBuffer = result.decryptedBuffer;
        verifiedSha512 = result.verifiedSha512;
      } catch (decryptErr) {
        console.error('Decryption failed:', decryptErr);
        throw new Error(decryptErr?.message || 'Cryptographic mismatch: This file was encrypted with a different key.');
      }

      const blob = new Blob([decryptedBuffer]);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = meta.originalName;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      showToast(`Decryption & SHA-512 verification successful (${(verifiedSha512 || '').substring(0, 10)}...)`, 'success');
      await loadDashboardData();
    } catch (err) {
      console.error('Decryption error:', err);
      const msg = err && err.message ? err.message : 'Cryptographic operation error';
      showToast(`Decryption failed: ${msg}`, 'error');
    }
  };

  // 6. Share Document (Wrap DEK with Recipient's Public Key)
  const handleShareDocument = async (e) => {
    e.preventDefault();
    if (!selectedDoc || !shareRecipientId) return;

    try {
      showToast('Wrapping DEK with recipient RSA Public Key...', 'info');

      const metaRes = await fetch(`/api/documents/${selectedDoc.id}/metadata`);
      if (!metaRes.ok) {
        const errMeta = await metaRes.json();
        throw new Error(errMeta.error || 'Failed to fetch document metadata');
      }
      const { document: meta } = await metaRes.json();

      const recipient = allUsers.find(u => u.id === shareRecipientId);
      if (!recipient || !recipient.publicKeyPem) {
        throw new Error('Recipient public key unavailable in MongoDB.');
      }

      let privKey = userPrivateKey;
      if (!privKey) {
        const pass = prompt('Enter your password to unlock your private key:');
        if (!pass) return;
        privKey = await loadAndDecryptPrivateKey(pass, currentUser.id);
        setUserPrivateKey(privKey);
      }

      const wrappedBuffer = base64ToBuffer(meta.userWrappedDEK);
      let rawDEK;
      try {
        rawDEK = await window.crypto.subtle.decrypt(
          { name: 'RSA-OAEP' },
          privKey,
          wrappedBuffer
        );
      } catch (decryptErr) {
        console.error('DEK unwrap failed:', decryptErr);
        throw new Error('Key mismatch: Document was encrypted with an older public key. Please delete and re-upload the file to share it.');
      }

      const recipientWrappedDEK = await wrapDEKForRecipient(rawDEK, recipient.publicKeyPem);

      let expiresAt = null;
      if (shareExpiryHours && !isNaN(shareExpiryHours)) {
        const d = new Date();
        d.setHours(d.getHours() + parseFloat(shareExpiryHours));
        expiresAt = d.toISOString();
      }

      const res = await fetch(`/api/documents/${selectedDoc.id}/share`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          recipientId: recipient.id,
          permission: sharePermission,
          wrappedDEK: recipientWrappedDEK,
          expiresAt
        })
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Failed to update document ACL in MongoDB');
      }

      showToast(`Document shared with ${recipient.fullName} (${sharePermission})`, 'success');
      setShowShareModal(false);
      setSelectedDoc(null);
      await loadDashboardData();
    } catch (err) {
      console.error('Sharing error:', err);
      const msg = err && err.message ? err.message : 'Cryptographic operation error';
      showToast(`Sharing failed: ${msg}`, 'error');
    }
  };

  // 7. Revoke Access
  const handleRevokeAccess = async (docId, recipientId, recipientName) => {
    if (!window.confirm(`Revoke access for ${recipientName}? The user will be immediately removed from the MongoDB document ACL.`)) {
      return;
    }

    try {
      const res = await fetch(`/api/documents/${docId}/revoke`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recipientId })
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Revocation failed');
      }

      showToast(`Access for ${recipientName} revoked. Immediate server enforcement active.`, 'success');
      await loadDashboardData();
    } catch (err) {
      showToast(`Revocation error: ${err.message}`, 'error');
    }
  };

  // 8. Cryptographic Hash Chain Verification (SHA-512)
  const handleVerifyAuditChain = async () => {
    try {
      showToast('Running recursive SHA-512 verification across all MongoDB audit blocks...', 'info');
      const res = await fetch('/api/audit/verify');
      const data = await res.json();
      setAuditVerification(data);

      if (data.valid) {
        showToast(`MongoDB audit ledger intact! Verified ${data.totalBlocks} blocks.`, 'success');
      } else {
        showToast(`AUDIT ALERT: Tampering detected at Block #${data.brokenIndex}!`, 'error');
      }
      await loadDashboardData();
    } catch (err) {
      showToast(`Audit verification error: ${err.message}`, 'error');
    }
  };

  // 9. Inspect Vault Disk Blob
  const handleInspectStorage = async (docId) => {
    try {
      const res = await fetch(`/api/adversarial/inspect-storage/${docId}`);
      if (!res.ok) throw new Error('Failed to inspect physical vault storage');
      const data = await res.json();
      setStorageInspection(data);
    } catch (err) {
      showToast(`Storage inspection error: ${err.message}`, 'error');
    }
  };

  // 10. Simulate Bit Flip
  const handleSimulateBitFlip = async (docId) => {
    if (!window.confirm('Simulate Bit-Flipping Attack: This will flip 1 bit in the raw ciphertext file on disk. When downloaded, AES-GCM authenticated tag verification must reject the file. Proceed?')) {
      return;
    }
    try {
      const res = await fetch(`/api/adversarial/tamper-blob/${docId}`, { method: 'POST' });
      const data = await res.json();
      showToast(`Bit 0 flipped in vault storage: ${data.message}`, 'warning');
      await loadDashboardData();
    } catch (err) {
      showToast(`Tamper simulation error: ${err.message}`, 'error');
    }
  };

  // 11. Simulate Audit Tamper
  const handleSimulateAuditTamper = async () => {
    if (!window.confirm('Simulate Audit Log Tampering: This will alter the action description of Block #1 in the MongoDB audit database without recalculating cryptographic hashes. Proceed?')) {
      return;
    }
    try {
      const res = await fetch('/api/adversarial/tamper-log', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ index: 1 })
      });
      const data = await res.json();
      showToast(`Block #1 modified in MongoDB. Click "Verify Hash-Chain" to demonstrate detection!`, 'warning');
      await loadDashboardData();
    } catch (err) {
      showToast(`Audit tampering error: ${err.message}`, 'error');
    }
  };

  const formatBytes = (bytes) => {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  };

  const getFileIcon = (type) => {
    const ext = (type || '').toLowerCase();
    if (ext === 'pdf') {
      return (
        <div className="w-10 h-10 rounded-lg bg-rose-50 border border-rose-100 flex items-center justify-center text-rose-500 font-bold text-xs shadow-xs">
          <FileText className="w-5 h-5 text-rose-500" />
        </div>
      );
    }
    if (['doc', 'docx', 'txt'].includes(ext)) {
      return (
        <div className="w-10 h-10 rounded-lg bg-blue-50 border border-blue-100 flex items-center justify-center text-blue-500 font-bold text-xs shadow-xs">
          <FileText className="w-5 h-5 text-blue-500" />
        </div>
      );
    }
    if (['zip', 'rar', 'tar', 'gz'].includes(ext)) {
      return (
        <div className="w-10 h-10 rounded-lg bg-purple-50 border border-purple-100 flex items-center justify-center text-purple-500 font-bold text-xs shadow-xs">
          <FileArchive className="w-5 h-5 text-purple-500" />
        </div>
      );
    }
    return (
      <div className="w-10 h-10 rounded-lg bg-slate-50 border border-slate-200 flex items-center justify-center text-slate-500 font-bold text-xs shadow-xs">
        <FileCode className="w-5 h-5 text-slate-500" />
      </div>
    );
  };

  // Filtered documents
  const filteredDocs = documents.filter(doc => {
    const matchesSearch = doc.originalName.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          doc.ownerName.toLowerCase().includes(searchQuery.toLowerCase());
    if (activeTab === 'mydocs') return matchesSearch && doc.isOwner;
    if (activeTab === 'shared') return matchesSearch && !doc.isOwner;
    return matchesSearch;
  });

  // ============================================================
  // VIEW A: DEDICATED LOGIN & SIGN UP INTERFACE (MONGODB BACKED)
  // ============================================================
  if (!currentUser) {
    return (
      <div className="min-h-screen w-full bg-[#0c1527] flex items-center justify-center p-4 font-sans select-none relative overflow-hidden">
        {/* Background glow effects */}
        <div className="absolute -top-40 -left-40 w-96 h-96 bg-blue-600/20 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute -bottom-40 -right-40 w-96 h-96 bg-emerald-600/15 rounded-full blur-3xl pointer-events-none" />

        <div className="max-w-md w-full bg-[#111c34] border border-[#1e2e4e] rounded-3xl p-8 shadow-2xl relative z-10 text-slate-200">
          {/* Logo & Header */}
          <div className="text-center mb-6">
            <div className="w-14 h-14 rounded-2xl bg-gradient-to-tr from-blue-600 to-indigo-500 flex items-center justify-center mx-auto mb-3 shadow-lg shadow-blue-500/25 text-white">
              <Shield className="w-7 h-7" />
            </div>
            <h1 className="text-2xl font-bold text-white tracking-wide">Vaultora</h1>
            <p className="text-xs uppercase font-semibold text-blue-400 tracking-widest mt-0.5">
              Secure Document Workspace
            </p>
            <div className="flex items-center justify-center gap-1.5 mt-2 text-[11px] text-slate-400">
              <Database className="w-3.5 h-3.5 text-emerald-400" />
              <span>MongoDB Cluster Integrated</span>
            </div>
          </div>

          {/* Toggle Tab */}
          <div className="grid grid-cols-2 p-1 bg-[#0c1527] rounded-xl mb-6 border border-[#1e2e4e]">
            <button
              onClick={() => { setAuthMode('login'); setAuthError(''); }}
              className={`py-2 text-xs font-bold rounded-lg transition-all ${
                authMode === 'login'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Sign In
            </button>
            <button
              onClick={() => { setAuthMode('register'); setAuthError(''); }}
              className={`py-2 text-xs font-bold rounded-lg transition-all ${
                authMode === 'register'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Create Account
            </button>
          </div>

          {/* Error Message */}
          {authError && (
            <div className="mb-4 p-3 bg-rose-500/10 border border-rose-500/30 rounded-xl text-xs text-rose-400 flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{authError}</span>
            </div>
          )}

          {/* Status Progress */}
          {cryptoStatus && (
            <div className="mb-4 p-3 bg-blue-500/10 border border-blue-500/30 rounded-xl text-xs text-blue-300 animate-pulse text-center">
              {cryptoStatus}
            </div>
          )}

          {/* Form */}
          <form onSubmit={authMode === 'login' ? handleLogin : handleRegister} className="space-y-4 text-xs">
            {authMode === 'login' && (
              <div className="mb-2">
                <label className="block text-slate-400 font-semibold mb-1.5">Quick Demo Accounts (Password: Password123!)</label>
                <div className="grid grid-cols-3 gap-2">
                  <button
                    type="button"
                    onClick={() => setAuthForm({ ...authForm, username: 'mashaf', password: 'Password123!' })}
                    className="p-2 bg-blue-600/20 border border-blue-500/40 rounded-xl text-center hover:bg-blue-600/30 transition-colors cursor-pointer"
                  >
                    <div className="font-bold text-blue-300">Mashaf</div>
                    <div className="text-[9px] text-blue-400">Admin</div>
                  </button>

                  <button
                    type="button"
                    onClick={() => setAuthForm({ ...authForm, username: 'ali', password: 'Password123!' })}
                    className="p-2 bg-[#0c1527] border border-[#1e2e4e] rounded-xl text-center hover:bg-[#15233e] transition-colors cursor-pointer"
                  >
                    <div className="font-bold text-slate-200">Ali</div>
                    <div className="text-[9px] text-slate-400">User</div>
                  </button>

                  <button
                    type="button"
                    onClick={() => setAuthForm({ ...authForm, username: 'farman', password: 'Password123!' })}
                    className="p-2 bg-[#0c1527] border border-[#1e2e4e] rounded-xl text-center hover:bg-[#15233e] transition-colors cursor-pointer"
                  >
                    <div className="font-bold text-slate-200">Farman</div>
                    <div className="text-[9px] text-slate-400">User</div>
                  </button>
                </div>
              </div>
            )}

            {authMode === 'register' && (
              <>
                <div>
                  <label className="block text-slate-400 font-semibold mb-1">Full Name</label>
                  <div className="relative">
                    <User className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                    <input
                      type="text"
                      required
                      placeholder="e.g. Mashaf Zaidi"
                      value={authForm.fullName}
                      onChange={(e) => setAuthForm({ ...authForm, fullName: e.target.value })}
                      className="w-full bg-[#0c1527] border border-[#1e2e4e] focus:border-blue-500 rounded-xl pl-9 pr-3 py-2.5 text-white placeholder-slate-600 focus:outline-none focus:ring-1 focus:ring-blue-500"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-slate-400 font-semibold mb-1">Email Address</label>
                  <div className="relative">
                    <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                    <input
                      type="email"
                      required
                      placeholder="name@organization.com"
                      value={authForm.email}
                      onChange={(e) => setAuthForm({ ...authForm, email: e.target.value })}
                      className="w-full bg-[#0c1527] border border-[#1e2e4e] focus:border-blue-500 rounded-xl pl-9 pr-3 py-2.5 text-white placeholder-slate-600 focus:outline-none focus:ring-1 focus:ring-blue-500"
                    />
                  </div>
                </div>
              </>
            )}

            <div>
              <label className="block text-slate-400 font-semibold mb-1">Username</label>
              <div className="relative">
                <User className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  required
                  placeholder="e.g. mashaf"
                  value={authForm.username}
                  onChange={(e) => setAuthForm({ ...authForm, username: e.target.value })}
                  className="w-full bg-[#0c1527] border border-[#1e2e4e] focus:border-blue-500 rounded-xl pl-9 pr-3 py-2.5 text-white placeholder-slate-600 focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
              </div>
            </div>

            <div>
              <label className="block text-slate-400 font-semibold mb-1">Password</label>
              <div className="relative">
                <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="password"
                  required
                  placeholder="Enter strong password"
                  value={authForm.password}
                  onChange={(e) => setAuthForm({ ...authForm, password: e.target.value })}
                  className="w-full bg-[#0c1527] border border-[#1e2e4e] focus:border-blue-500 rounded-xl pl-9 pr-3 py-2.5 text-white placeholder-slate-600 focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
              </div>
              <p className="text-[10px] text-slate-500 mt-1">
                Password is used to derive PBKDF2 local key encryption key and hashed with Argon2id.
              </p>
            </div>

            {authMode === 'register' && (
              <div>
                <label className="block text-slate-400 font-semibold mb-1.5">Select System Role</label>
                <div className="grid grid-cols-3 gap-2">
                  <button
                    type="button"
                    onClick={() => setAuthForm({ ...authForm, role: 'admin' })}
                    className={`p-2.5 rounded-xl border text-center transition-all ${
                      authForm.role === 'admin'
                        ? 'bg-blue-600/20 border-blue-500 text-blue-300 font-bold'
                        : 'bg-[#0c1527] border-[#1e2e4e] text-slate-400 hover:text-white'
                    }`}
                  >
                    <div className="text-xs">Admin</div>
                    <div className="text-[9px] opacity-75">Full Access</div>
                  </button>

                  <button
                    type="button"
                    onClick={() => setAuthForm({ ...authForm, role: 'user' })}
                    className={`p-2.5 rounded-xl border text-center transition-all ${
                      authForm.role === 'user'
                        ? 'bg-blue-600/20 border-blue-500 text-blue-300 font-bold'
                        : 'bg-[#0c1527] border-[#1e2e4e] text-slate-400 hover:text-white'
                    }`}
                  >
                    <div className="text-xs">User</div>
                    <div className="text-[9px] opacity-75">Standard</div>
                  </button>

                  <button
                    type="button"
                    onClick={() => setAuthForm({ ...authForm, role: 'auditor' })}
                    className={`p-2.5 rounded-xl border text-center transition-all ${
                      authForm.role === 'auditor'
                        ? 'bg-blue-600/20 border-blue-500 text-blue-300 font-bold'
                        : 'bg-[#0c1527] border-[#1e2e4e] text-slate-400 hover:text-white'
                    }`}
                  >
                    <div className="text-xs">Auditor</div>
                    <div className="text-[9px] opacity-75">Logs Only</div>
                  </button>
                </div>
              </div>
            )}

            <button
              type="submit"
              disabled={!!cryptoStatus}
              className="w-full mt-4 py-3 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 active:scale-[0.99] text-white font-bold rounded-xl shadow-lg shadow-blue-600/30 transition-all cursor-pointer disabled:opacity-50"
            >
              {authMode === 'login' ? 'Sign In to Workspace' : 'Create Encrypted Account in MongoDB'}
            </button>
          </form>

          {/* Security Guarantee Footer */}
          <div className="mt-6 pt-4 border-t border-[#1e2e4e] text-center">
            <div className="text-[10px] text-slate-400 flex items-center justify-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
              <span>Zero-Knowledge Envelope Encryption (AES-GCM-256 + RSA-OAEP-2048)</span>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // ============================================================
  // VIEW B: AUTHENTICATED WORKSPACE (Pixel-Matched to Screenshot)
  // ============================================================
  return (
    <div className="flex h-screen w-full bg-[#f8fafc] text-slate-800 overflow-hidden font-sans">
      {/* 1. Left Sidebar */}
      <aside className="w-64 bg-[#0c1527] text-slate-300 flex flex-col justify-between border-r border-[#1e293b] select-none shrink-0">
        <div>
          {/* Logo & Brand Header */}
          <div className="p-5 flex items-center gap-3 border-b border-[#17233d]">
            <div className="w-9 h-9 rounded-xl bg-blue-600 flex items-center justify-center shadow-lg shadow-blue-500/30 text-white">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="font-bold text-lg text-white tracking-wide">Vaultora</div>
              <div className="text-[10px] uppercase font-semibold text-blue-400 tracking-wider -mt-0.5">
                SECURE WORKSPACE
              </div>
            </div>
          </div>

          {/* Navigation Links */}
          <div className="px-3 py-4">
            <div className="text-[11px] font-semibold text-slate-400 px-3 uppercase tracking-wider mb-2">
              Workspace
            </div>
            <nav className="space-y-1">
              <button
                onClick={() => setActiveTab('overview')}
                className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-sm font-medium transition-colors cursor-pointer ${
                  activeTab === 'overview'
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'text-slate-300 hover:bg-[#15233e] hover:text-white'
                }`}
              >
                <div className="flex items-center gap-3">
                  <HardDrive className="w-4 h-4" />
                  <span>Overview</span>
                </div>
              </button>

              <button
                onClick={() => setActiveTab('mydocs')}
                className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-sm font-medium transition-colors cursor-pointer ${
                  activeTab === 'mydocs'
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'text-slate-300 hover:bg-[#15233e] hover:text-white'
                }`}
              >
                <div className="flex items-center gap-3">
                  <FileText className="w-4 h-4" />
                  <span>My documents</span>
                </div>
                <span className="text-xs bg-slate-800/80 text-slate-300 px-2 py-0.5 rounded-full border border-slate-700">
                  {documents.filter(d => d.isOwner).length}
                </span>
              </button>

              <button
                onClick={() => setActiveTab('shared')}
                className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-sm font-medium transition-colors cursor-pointer ${
                  activeTab === 'shared'
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'text-slate-300 hover:bg-[#15233e] hover:text-white'
                }`}
              >
                <div className="flex items-center gap-3">
                  <Users className="w-4 h-4" />
                  <span>Shared with me</span>
                </div>
                <span className="text-xs bg-slate-800/80 text-slate-300 px-2 py-0.5 rounded-full border border-slate-700">
                  {documents.filter(d => !d.isOwner).length}
                </span>
              </button>

              <button className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-slate-400 hover:bg-[#15233e] hover:text-slate-200 transition-colors">
                <Star className="w-4 h-4" />
                <span>Starred</span>
              </button>

              <button className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-slate-400 hover:bg-[#15233e] hover:text-slate-200 transition-colors">
                <Clock className="w-4 h-4" />
                <span>Recent</span>
              </button>

              <button className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-slate-400 hover:bg-[#15233e] hover:text-slate-200 transition-colors">
                <Archive className="w-4 h-4" />
                <span>Archive</span>
              </button>
            </nav>

            <div className="text-[11px] font-semibold text-slate-400 px-3 uppercase tracking-wider mt-6 mb-2">
              Manage
            </div>
            <nav className="space-y-1">
              <button className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-slate-400 hover:bg-[#15233e] hover:text-slate-200 transition-colors">
                <Trash2 className="w-4 h-4" />
                <span>Trash</span>
              </button>
              <button
                onClick={() => setShowSecurityCenter(true)}
                className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-slate-400 hover:bg-[#15233e] hover:text-slate-200 transition-colors cursor-pointer"
              >
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                <span>Security & Audit</span>
              </button>
            </nav>
          </div>
        </div>

        {/* Storage Bar Footer */}
        <div className="p-4 m-3 bg-[#131f38] border border-slate-800 rounded-xl">
          <div className="flex justify-between items-center text-xs mb-1.5 font-medium">
            <span className="text-slate-400">Vault Storage</span>
            <span className="text-white font-semibold">{formatBytes(metrics.totalBytes)}</span>
          </div>
          <div className="w-full h-1.5 bg-slate-700/60 rounded-full overflow-hidden">
            <div className="h-full bg-blue-500 rounded-full" style={{ width: '15%' }} />
          </div>
          <div className="flex items-center justify-between mt-2.5 text-[11px] text-slate-400">
            <span>MongoDB Encrypted</span>
            <span className="text-emerald-400 font-semibold">100% E2EE</span>
          </div>
        </div>
      </aside>

      {/* 2. Main Content Area */}
      <div className="flex-1 flex flex-col overflow-y-auto">
        {/* Top Navbar */}
        <header className="h-16 bg-white border-b border-slate-200/80 px-8 flex items-center justify-between shrink-0">
          {/* Search Bar */}
          <div className="relative w-96">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search your secure documents..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-slate-50 hover:bg-slate-100/70 focus:bg-white text-sm pl-10 pr-4 py-2 rounded-xl border border-slate-200 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all text-slate-700"
            />
          </div>

          {/* User Profile & Actions */}
          <div className="flex items-center gap-4">
            <button
              onClick={() => setShowSecurityCenter(true)}
              title="Audit Verification Status"
              className="relative p-2 text-slate-500 hover:text-slate-700 hover:bg-slate-100 rounded-xl transition-colors cursor-pointer"
            >
              <Bell className="w-5 h-5" />
              <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-emerald-500 rounded-full ring-2 ring-white" />
            </button>

            {/* Profile Pill */}
            <div className="flex items-center gap-3 pl-2 border-l border-slate-200">
              <div className="w-9 h-9 rounded-full bg-blue-100 border border-blue-200 flex items-center justify-center text-blue-700 font-semibold text-xs shadow-xs">
                {currentUser?.fullName?.split(' ').map(n => n[0]).join('') || 'U'}
              </div>
              <div className="text-left text-xs">
                <div className="font-semibold text-slate-800">
                  {currentUser?.fullName}
                </div>
                <div className="text-slate-400 capitalize">
                  {currentUser?.role === 'admin' ? 'Administrator' : currentUser?.role}
                </div>
              </div>
              <button
                onClick={handleLogout}
                title="Sign Out"
                className="p-1.5 text-slate-400 hover:text-rose-600 hover:bg-rose-50 rounded-lg transition-colors cursor-pointer ml-1"
              >
                <LogOut className="w-4 h-4" />
              </button>
            </div>
          </div>
        </header>

        {/* Main Content View */}
        <main className="p-8 max-w-7xl w-full mx-auto space-y-6">
          {/* Welcome Header & Upload Action */}
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <div className="text-[11px] font-bold uppercase tracking-wider text-blue-600 mb-1">
                SECURE WORKSPACE
              </div>
              <h1 className="text-2xl font-bold text-slate-900">
                Good morning, {currentUser?.fullName?.split(' ')[0]}
              </h1>
              <p className="text-xs text-slate-500 mt-0.5">
                Here's what's happening with your documents today.
              </p>
            </div>

            <button
              onClick={() => setShowUploadModal(true)}
              className="inline-flex items-center gap-2 bg-blue-600 hover:bg-blue-700 active:bg-blue-800 text-white font-medium text-sm px-5 py-2.5 rounded-xl shadow-sm hover:shadow transition-all self-start md:self-auto cursor-pointer"
            >
              <Plus className="w-4 h-4" />
              <span>Upload document</span>
            </button>
          </div>

          {/* 4 Metric Stat Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Card 1: Total Documents */}
            <div className="bg-white rounded-2xl p-5 border border-slate-200/80 shadow-xs flex flex-col justify-between">
              <div className="flex items-center justify-between text-slate-500 text-xs font-medium">
                <span>Total documents</span>
                <div className="w-8 h-8 rounded-lg bg-blue-50 text-blue-600 flex items-center justify-center">
                  <FileText className="w-4 h-4" />
                </div>
              </div>
              <div className="mt-3">
                <div className="text-3xl font-bold text-slate-900">
                  {metrics.totalDocuments}
                </div>
                <div className="text-[11px] text-emerald-600 font-medium mt-1 flex items-center gap-1">
                  <span>MongoDB Persistent</span>
                </div>
              </div>
            </div>

            {/* Card 2: Shared With You */}
            <div className="bg-white rounded-2xl p-5 border border-slate-200/80 shadow-xs flex flex-col justify-between">
              <div className="flex items-center justify-between text-slate-500 text-xs font-medium">
                <span>Shared with you</span>
                <div className="w-8 h-8 rounded-lg bg-purple-50 text-purple-600 flex items-center justify-center">
                  <Users className="w-4 h-4" />
                </div>
              </div>
              <div className="mt-3">
                <div className="text-3xl font-bold text-slate-900">
                  {String(metrics.sharedWithYou).padStart(2, '0')}
                </div>
                <div className="text-[11px] text-slate-500 font-medium mt-1 flex items-center gap-1">
                  <span>Asymmetric Wrapped DEK</span>
                </div>
              </div>
            </div>

            {/* Card 3: Protected Files */}
            <div className="bg-white rounded-2xl p-5 border border-slate-200/80 shadow-xs flex flex-col justify-between">
              <div className="flex items-center justify-between text-slate-500 text-xs font-medium">
                <span>Protected files</span>
                <div className="w-8 h-8 rounded-lg bg-emerald-50 text-emerald-600 flex items-center justify-center">
                  <Lock className="w-4 h-4" />
                </div>
              </div>
              <div className="mt-3">
                <div className="text-3xl font-bold text-slate-900">
                  {metrics.protectedFiles}
                </div>
                <div className="text-[11px] text-emerald-600 font-medium mt-1 flex items-center gap-1">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>100% encrypted</span>
                </div>
              </div>
            </div>

            {/* Card 4: Storage Used */}
            <div className="bg-white rounded-2xl p-5 border border-slate-200/80 shadow-xs flex flex-col justify-between">
              <div className="flex items-center justify-between text-slate-500 text-xs font-medium">
                <span>Storage used</span>
                <div className="w-8 h-8 rounded-lg bg-orange-50 text-orange-600 flex items-center justify-center">
                  <HardDrive className="w-4 h-4" />
                </div>
              </div>
              <div className="mt-3">
                <div className="text-3xl font-bold text-slate-900">
                  {formatBytes(metrics.totalBytes)}
                </div>
                <div className="text-[11px] text-slate-500 font-medium mt-1 flex items-center gap-1">
                  <span>Encrypted /vault/ blobs</span>
                </div>
              </div>
            </div>
          </div>

          {/* Grid: Left (Recent Documents Table) + Right (Security Status & Activity) */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Left 2 Cols: Documents Table */}
            <div className="lg:col-span-2 bg-white rounded-2xl border border-slate-200/80 shadow-xs overflow-hidden">
              <div className="p-5 border-b border-slate-100 flex items-center justify-between">
                <div>
                  <h2 className="text-base font-bold text-slate-900">Recent documents</h2>
                  <p className="text-xs text-slate-400">Your latest secured files in MongoDB.</p>
                </div>
                <button
                  onClick={() => setActiveTab('overview')}
                  className="text-xs font-semibold text-blue-600 hover:text-blue-700 cursor-pointer"
                >
                  View all documents
                </button>
              </div>

              {/* Table */}
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs text-slate-600">
                  <thead className="bg-slate-50/70 text-[10px] uppercase font-bold text-slate-400 border-b border-slate-100 tracking-wider">
                    <tr>
                      <th className="py-3 px-5">Name</th>
                      <th className="py-3 px-4">Owner</th>
                      <th className="py-3 px-4">Modified</th>
                      <th className="py-3 px-4">Sharing</th>
                      <th className="py-3 px-4 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {filteredDocs.length === 0 ? (
                      <tr>
                        <td colSpan="5" className="py-12 text-center text-slate-400">
                          <Lock className="w-8 h-8 mx-auto mb-2 text-slate-300" />
                          <p className="font-semibold text-slate-600">No encrypted documents uploaded yet.</p>
                          <p className="text-[11px] mt-0.5">Click "+ Upload document" to test client-side envelope encryption.</p>
                        </td>
                      </tr>
                    ) : (
                      filteredDocs.map((doc) => (
                        <tr key={doc.id} className="hover:bg-slate-50/60 transition-colors group">
                          {/* Name + File Type */}
                          <td className="py-3 px-5">
                            <div className="flex items-center gap-3">
                              {getFileIcon(doc.fileType)}
                              <div>
                                <div className="font-semibold text-slate-800 text-xs group-hover:text-blue-600 transition-colors">
                                  {doc.originalName}
                                </div>
                                <div className="text-[10px] text-slate-400 uppercase tracking-wider">
                                  {doc.fileType} • {formatBytes(doc.size)}
                                </div>
                              </div>
                            </div>
                          </td>

                          {/* Owner */}
                          <td className="py-3 px-4 font-medium text-slate-600">
                            {doc.isOwner ? 'You' : doc.ownerName}
                          </td>

                          {/* Modified */}
                          <td className="py-3 px-4 text-slate-400 text-[11px]">
                            {new Date(doc.updatedAt || doc.createdAt).toLocaleDateString('en-US', {
                              month: 'short',
                              day: '2-digit',
                              year: 'numeric'
                            })}
                          </td>

                          {/* Sharing Avatars */}
                          <td className="py-3 px-4">
                            <div className="flex items-center -space-x-1.5">
                              {doc.sharedUsers?.slice(0, 3).map((u, i) => (
                                <div
                                  key={i}
                                  title={`${u.userName} (${u.permission})`}
                                  className={`w-6 h-6 rounded-full border-2 border-white flex items-center justify-center text-[9px] font-bold text-white ${
                                    i === 0 ? 'bg-blue-500' : i === 1 ? 'bg-amber-500' : 'bg-emerald-500'
                                  }`}
                                >
                                  {u.userName ? u.userName[0] : 'U'}
                                </div>
                              ))}
                              {doc.sharedUsers?.length > 3 && (
                                <div className="w-6 h-6 rounded-full bg-slate-200 border-2 border-white flex items-center justify-center text-[9px] font-semibold text-slate-600">
                                  +{doc.sharedUsers.length - 3}
                                </div>
                              )}
                            </div>
                          </td>

                          {/* Action Menu */}
                          <td className="py-3 px-4 text-right relative">
                            <button
                              onClick={() => setActiveMenuDocId(activeMenuDocId === doc.id ? null : doc.id)}
                              className="p-1.5 text-slate-400 hover:text-slate-600 rounded-lg hover:bg-slate-100 transition-colors cursor-pointer"
                            >
                              <MoreVertical className="w-4 h-4" />
                            </button>

                            {/* Dropdown Menu */}
                            {activeMenuDocId === doc.id && (
                              <div
                                onMouseLeave={() => setActiveMenuDocId(null)}
                                className="absolute right-4 top-10 w-52 bg-white rounded-xl shadow-xl border border-slate-200 py-1.5 z-20 text-left text-xs"
                              >
                                <button
                                  onClick={() => {
                                    setActiveMenuDocId(null);
                                    handleDownloadAndDecrypt(doc);
                                  }}
                                  className="w-full flex items-center gap-2 px-3.5 py-2 text-slate-700 hover:bg-blue-50 hover:text-blue-600 cursor-pointer"
                                >
                                  <Download className="w-3.5 h-3.5 text-blue-600" />
                                  <span>Download & Decrypt</span>
                                </button>

                                <button
                                  onClick={() => {
                                    setActiveMenuDocId(null);
                                    setSelectedDoc(doc);
                                    setShowShareModal(true);
                                  }}
                                  className="w-full flex items-center gap-2 px-3.5 py-2 text-slate-700 hover:bg-slate-50 cursor-pointer"
                                >
                                  <Share2 className="w-3.5 h-3.5 text-slate-400" />
                                  <span>Share with User (Wrap DEK)</span>
                                </button>

                                <button
                                  onClick={() => {
                                    setActiveMenuDocId(null);
                                    handleInspectStorage(doc.id);
                                  }}
                                  className="w-full flex items-center gap-2 px-3.5 py-2 text-slate-700 hover:bg-slate-50 cursor-pointer"
                                >
                                  <Eye className="w-3.5 h-3.5 text-slate-400" />
                                  <span>Inspect Vault Disk Blob</span>
                                </button>

                                <button
                                  onClick={() => {
                                    setActiveMenuDocId(null);
                                    handleSimulateBitFlip(doc.id);
                                  }}
                                  className="w-full flex items-center gap-2 px-3.5 py-2 text-amber-600 hover:bg-amber-50 cursor-pointer"
                                >
                                  <AlertTriangle className="w-3.5 h-3.5 text-amber-500" />
                                  <span>Simulate Bit-Flip Tamper</span>
                                </button>

                                {doc.isOwner && (
                                  <button
                                    onClick={async () => {
                                      setActiveMenuDocId(null);
                                      if (window.confirm(`Delete "${doc.originalName}" permanently from disk vault and MongoDB?`)) {
                                        await fetch(`/api/documents/${doc.id}`, { method: 'DELETE' });
                                        showToast('Document deleted.', 'info');
                                        await loadDashboardData();
                                      }
                                    }}
                                    className="w-full flex items-center gap-2 px-3.5 py-2 text-rose-600 hover:bg-rose-50 border-t border-slate-100 cursor-pointer"
                                  >
                                    <Trash2 className="w-3.5 h-3.5 text-rose-500" />
                                    <span>Delete Document</span>
                                  </button>
                                )}
                              </div>
                            )}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Right 1 Col: Security Status + Recent Activity */}
            <div className="space-y-6">
              {/* Security Status Card */}
              <div className="bg-white rounded-2xl border border-slate-200/80 p-5 shadow-xs">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-bold text-slate-900">Security status</h3>
                    <p className="text-[11px] text-slate-400">All systems protected</p>
                  </div>
                  <div className="w-7 h-7 rounded-lg bg-emerald-50 text-emerald-600 flex items-center justify-center">
                    <Shield className="w-4 h-4" />
                  </div>
                </div>

                <div className="mt-4">
                  <div className="flex justify-between items-center text-xs font-semibold mb-1">
                    <span className="text-slate-600">Workspace security</span>
                    <span className="text-emerald-600">Excellent</span>
                  </div>
                  <div className="w-full h-2 bg-slate-100 rounded-full overflow-hidden">
                    <div className="h-full bg-emerald-500 rounded-full" style={{ width: '96%' }} />
                  </div>
                </div>

                <div className="mt-4 space-y-2 text-xs text-slate-600">
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0" />
                    <span>End-to-end encryption active</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0" />
                    <span>Argon2id password hashing on</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0" />
                    <span>MongoDB tamper-evident audit ledger</span>
                  </div>
                </div>

                <button
                  onClick={() => setShowSecurityCenter(true)}
                  className="w-full mt-5 py-2.5 px-4 bg-slate-50 hover:bg-slate-100 border border-slate-200 text-slate-700 text-xs font-semibold rounded-xl transition-colors cursor-pointer"
                >
                  View security center
                </button>
              </div>

              {/* Recent Activity Card */}
              <div className="bg-white rounded-2xl border border-slate-200/80 p-5 shadow-xs">
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <h3 className="text-sm font-bold text-slate-900">Recent activity</h3>
                    <p className="text-[11px] text-slate-400">Your security trail</p>
                  </div>
                  <button
                    onClick={loadDashboardData}
                    title="Refresh Trail"
                    className="text-slate-400 hover:text-slate-600 p-1 cursor-pointer"
                  >
                    <RefreshCw className="w-3.5 h-3.5" />
                  </button>
                </div>

                <div className="space-y-3.5">
                  {auditLogs.length === 0 ? (
                    <div className="text-xs text-slate-400 text-center py-4">
                      No security events recorded yet.
                    </div>
                  ) : (
                    auditLogs.slice(-4).reverse().map((log) => (
                      <div key={log.index} className="flex items-start gap-3 text-xs">
                        <div className={`w-7 h-7 rounded-lg flex items-center justify-center shrink-0 mt-0.5 ${
                          log.outcome === 'DENIED'
                            ? 'bg-rose-50 text-rose-500'
                            : log.action.includes('UPLOAD') || log.action.includes('SHARE')
                            ? 'bg-blue-50 text-blue-600'
                            : 'bg-emerald-50 text-emerald-600'
                        }`}>
                          {log.outcome === 'DENIED' ? (
                            <AlertTriangle className="w-3.5 h-3.5" />
                          ) : log.action.includes('SHARE') ? (
                            <Users className="w-3.5 h-3.5" />
                          ) : (
                            <ShieldCheck className="w-3.5 h-3.5" />
                          )}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="font-semibold text-slate-800 truncate">
                            {log.actorName} • {log.action.replace(/_/g, ' ')}
                          </div>
                          <div className="text-[11px] text-slate-400 truncate">
                            {log.targetDocName || (log.details?.role ? `Role: ${log.details.role}` : 'Verified')}
                          </div>
                          <div className="text-[10px] text-slate-400 mt-0.5">
                            {new Date(log.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                          </div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          </div>
        </main>
      </div>

      {/* 3. Upload Modal */}
      {showUploadModal && (
        <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-2xl max-w-md w-full p-6 shadow-2xl border border-slate-200">
            <div className="flex items-center justify-between pb-4 border-b border-slate-100">
              <div className="flex items-center gap-2 text-slate-900 font-bold text-base">
                <Lock className="w-5 h-5 text-blue-600" />
                <span>Upload Encrypted Document</span>
              </div>
              <button onClick={() => setShowUploadModal(false)} className="text-slate-400 hover:text-slate-600 cursor-pointer">
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleFileUpload} className="mt-4 space-y-4">
              <div className="border-2 border-dashed border-slate-200 hover:border-blue-400 rounded-xl p-6 text-center cursor-pointer transition-colors bg-slate-50/50">
                <input
                  type="file"
                  id="fileUpload"
                  onChange={(e) => setUploadFile(e.target.files[0])}
                  className="hidden"
                />
                <label htmlFor="fileUpload" className="cursor-pointer">
                  <div className="w-12 h-12 rounded-xl bg-blue-50 text-blue-600 flex items-center justify-center mx-auto mb-2">
                    <FileText className="w-6 h-6" />
                  </div>
                  <div className="text-sm font-semibold text-slate-700">
                    {uploadFile ? uploadFile.name : 'Click to select document'}
                  </div>
                  <div className="text-xs text-slate-400 mt-1">
                    {uploadFile ? `${formatBytes(uploadFile.size)} selected` : 'Files will be encrypted locally before transit'}
                  </div>
                </label>
              </div>

              <div className="bg-blue-50/70 border border-blue-100 rounded-xl p-3 text-xs text-blue-800 space-y-1">
                <div className="font-semibold flex items-center gap-1.5">
                  <Shield className="w-3.5 h-3.5" />
                  Zero-Knowledge Guarantee:
                </div>
                <p className="text-[11px] text-blue-700">
                  The client browser generates an AES-256-GCM symmetric key and encrypts the file before sending. The server and MongoDB never receive cleartext.
                </p>
              </div>

              {uploadProgress && (
                <div className="text-xs font-semibold text-blue-600 animate-pulse text-center">
                  {uploadProgress}
                </div>
              )}

              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowUploadModal(false)}
                  className="px-4 py-2 text-xs font-semibold text-slate-600 hover:bg-slate-100 rounded-xl transition-colors cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={!uploadFile || !!uploadProgress}
                  className="px-5 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700 rounded-xl transition-colors shadow-xs disabled:opacity-50 cursor-pointer"
                >
                  {uploadProgress ? 'Encrypting...' : 'Encrypt & Upload'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* 4. Share Modal */}
      {showShareModal && selectedDoc && (
        <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-2xl max-w-md w-full p-6 shadow-2xl border border-slate-200">
            <div className="flex items-center justify-between pb-4 border-b border-slate-100">
              <div className="flex items-center gap-2 text-slate-900 font-bold text-base">
                <Share2 className="w-5 h-5 text-blue-600" />
                <span>Share "{selectedDoc.originalName}"</span>
              </div>
              <button onClick={() => setShowShareModal(false)} className="text-slate-400 hover:text-slate-600 cursor-pointer">
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleShareDocument} className="mt-4 space-y-4 text-xs">
              <div>
                <label className="block text-slate-700 font-semibold mb-1">Select Registered MongoDB Recipient</label>
                {allUsers.filter(u => u.id !== currentUser.id).length === 0 ? (
                  <div className="p-3 bg-amber-50 border border-amber-200 rounded-xl text-amber-700 text-xs">
                    No other users registered in MongoDB yet. Register another account from the login screen to test cross-user sharing.
                  </div>
                ) : (
                  <select
                    value={shareRecipientId}
                    onChange={(e) => setShareRecipientId(e.target.value)}
                    className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2.5 text-slate-800 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    {allUsers
                      .filter(u => u.id !== currentUser.id)
                      .map(u => (
                        <option key={u.id} value={u.id}>
                          {u.fullName} ({u.role}) - @{u.username}
                        </option>
                      ))}
                  </select>
                )}
              </div>

              <div>
                <label className="block text-slate-700 font-semibold mb-1">Permission Level</label>
                <select
                  value={sharePermission}
                  onChange={(e) => setSharePermission(e.target.value)}
                  className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2.5 text-slate-800 focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="viewer">Viewer (Read & Decrypt only)</option>
                  <option value="editor">Editor (Read, Decrypt & Share)</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-700 font-semibold mb-1">
                  Access Expiration (Temporal Least Privilege)
                </label>
                <select
                  value={shareExpiryHours}
                  onChange={(e) => setShareExpiryHours(e.target.value)}
                  className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2.5 text-slate-800 focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="">Never Expires</option>
                  <option value="1">1 Hour</option>
                  <option value="24">24 Hours</option>
                  <option value="168">7 Days</option>
                </select>
              </div>

              <div className="flex justify-end gap-3 pt-3">
                <button
                  type="button"
                  onClick={() => setShowShareModal(false)}
                  className="px-4 py-2 text-slate-600 hover:bg-slate-100 rounded-xl font-medium cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={allUsers.filter(u => u.id !== currentUser.id).length === 0}
                  className="px-5 py-2 text-white bg-blue-600 hover:bg-blue-700 rounded-xl font-semibold shadow-xs disabled:opacity-50 cursor-pointer"
                >
                  Wrap DEK & Grant Access
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* 5. Security Center & Audit Ledger Modal */}
      {showSecurityCenter && (
        <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-2xl max-w-4xl w-full max-h-[90vh] flex flex-col p-6 shadow-2xl border border-slate-200">
            <div className="flex items-center justify-between pb-4 border-b border-slate-100 shrink-0">
              <div className="flex items-center gap-2.5">
                <ShieldCheck className="w-6 h-6 text-emerald-600" />
                <div>
                  <h2 className="text-base font-bold text-slate-900">Security Center & Audit Ledger</h2>
                  <p className="text-xs text-slate-400">
                    MongoDB Cryptographic SHA-512 Hash-Chained Verification & Adversarial Tests
                  </p>
                </div>
              </div>
              <button onClick={() => setShowSecurityCenter(false)} className="text-slate-400 hover:text-slate-600 cursor-pointer">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="py-4 shrink-0 flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <button
                  onClick={handleVerifyAuditChain}
                  className="px-4 py-2 bg-emerald-600 hover:bg-emerald-700 active:bg-emerald-800 text-white font-semibold text-xs rounded-xl shadow-xs transition-colors flex items-center gap-2 cursor-pointer"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  <span>Verify Hash-Chain Integrity</span>
                </button>

                {currentUser?.role === 'admin' && (
                  <button
                    onClick={handleSimulateAuditTamper}
                    className="px-3.5 py-2 bg-amber-50 hover:bg-amber-100 text-amber-700 border border-amber-200 font-semibold text-xs rounded-xl transition-colors cursor-pointer"
                  >
                    Simulate Audit Tampering (Part 3)
                  </button>
                )}
              </div>

              {auditVerification && (
                <div className={`px-3 py-1.5 rounded-xl text-xs font-semibold flex items-center gap-2 ${
                  auditVerification.valid
                    ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                    : 'bg-rose-50 text-rose-700 border border-rose-200'
                }`}>
                  {auditVerification.valid ? (
                    <>
                      <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                      <span>Ledger Valid ({auditVerification.totalBlocks} Blocks in MongoDB)</span>
                    </>
                  ) : (
                    <>
                      <AlertTriangle className="w-4 h-4 text-rose-500" />
                      <span>Tamper Detected at #{auditVerification.brokenIndex}: {auditVerification.reason}</span>
                    </>
                  )}
                </div>
              )}
            </div>

            <div className="flex-1 overflow-y-auto border border-slate-200 rounded-xl">
              <table className="w-full text-left text-xs text-slate-700">
                <thead className="bg-slate-50 text-[10px] uppercase font-bold text-slate-400 sticky top-0 border-b border-slate-200">
                  <tr>
                    <th className="py-2.5 px-3">#</th>
                    <th className="py-2.5 px-3">Timestamp</th>
                    <th className="py-2.5 px-3">Actor</th>
                    <th className="py-2.5 px-3">Action</th>
                    <th className="py-2.5 px-3">Outcome</th>
                    <th className="py-2.5 px-3">Prev Hash / Curr Hash</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 font-mono text-[11px]">
                  {auditLogs.map((log) => (
                    <tr key={log.index} className="hover:bg-slate-50">
                      <td className="py-2.5 px-3 font-semibold text-slate-500">{log.index}</td>
                      <td className="py-2.5 px-3 text-slate-500 font-sans">
                        {new Date(log.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="py-2.5 px-3 font-sans">
                        <span className="font-semibold text-slate-800">{log.actorName}</span>
                        <span className="text-[10px] text-slate-400 block capitalize">({log.actorRole})</span>
                      </td>
                      <td className="py-2.5 px-3 font-sans font-medium text-slate-800">
                        {log.action}
                        {log.targetDocName && (
                          <span className="block text-[10px] text-slate-400 truncate max-w-xs">
                            {log.targetDocName}
                          </span>
                        )}
                      </td>
                      <td className="py-2.5 px-3">
                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${
                          log.outcome === 'SUCCESS'
                            ? 'bg-emerald-50 text-emerald-700'
                            : 'bg-rose-50 text-rose-700'
                        }`}>
                          {log.outcome}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-[10px] text-slate-500">
                        <div>prev: {log.prevHash?.substring(0, 12)}...</div>
                        <div className="text-blue-600 font-semibold">curr: {log.currHash?.substring(0, 12)}...</div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="pt-4 flex justify-end shrink-0">
              <button
                onClick={() => setShowSecurityCenter(false)}
                className="px-5 py-2 text-xs font-semibold bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-xl cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 6. Storage Inspection Modal */}
      {storageInspection && (
        <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-2xl max-w-lg w-full p-6 shadow-2xl border border-slate-200">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100">
              <div className="flex items-center gap-2 text-slate-900 font-bold text-sm">
                <HardDrive className="w-5 h-5 text-blue-600" />
                <span>Physical Disk Inspection (/vault/{storageInspection.blobFileName})</span>
              </div>
              <button onClick={() => setStorageInspection(null)} className="text-slate-400 hover:text-slate-600 cursor-pointer">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="mt-4 space-y-3 text-xs text-slate-700 font-sans">
              <div className="bg-slate-50 border border-slate-200 rounded-xl p-3 space-y-1.5 font-mono text-[11px]">
                <div><span className="text-slate-400">File Name:</span> {storageInspection.blobFileName}</div>
                <div><span className="text-slate-400">Size:</span> {storageInspection.sizeBytes} bytes</div>
                <div><span className="text-slate-400">Shannon Entropy:</span> <span className="text-emerald-600 font-bold">{storageInspection.shannonEntropy}</span></div>
                <div><span className="text-slate-400">Hex Sample:</span> {storageInspection.first32BytesHex}</div>
                <div><span className="text-slate-400">ASCII Preview:</span> {storageInspection.asciiPreview}</div>
              </div>

              <div className="p-3 bg-emerald-50 border border-emerald-200 rounded-xl text-emerald-800 text-xs">
                <strong>Verdict:</strong> {storageInspection.verdict}
              </div>
            </div>

            <div className="mt-4 flex justify-end">
              <button
                onClick={() => setStorageInspection(null)}
                className="px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold rounded-xl cursor-pointer"
              >
                Close Inspection
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Toast Notification */}
      {notification && (
        <div className={`fixed bottom-6 right-6 px-4 py-3 rounded-2xl shadow-xl border flex items-center gap-3 text-xs font-semibold z-50 animate-bounce ${
          notification.type === 'error'
            ? 'bg-rose-600 text-white border-rose-700'
            : notification.type === 'warning'
            ? 'bg-amber-500 text-white border-amber-600'
            : 'bg-slate-900 text-white border-slate-800'
        }`}>
          {notification.type === 'error' ? (
            <AlertCircle className="w-4 h-4 shrink-0" />
          ) : (
            <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
          )}
          <span>{notification.message}</span>
        </div>
      )}
    </div>
  );
}
