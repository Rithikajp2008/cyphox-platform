const fs = require('fs');
const path = require('path');
const { DATA_DIR, STORAGE_DIR, RECOVERED_DIR, DELETED_VAULT_DIR, BACKUP_DIR, CERTIFICATES_DIR } = require('../config/config');

// Ensure all data directories exist
[DATA_DIR, STORAGE_DIR, RECOVERED_DIR, DELETED_VAULT_DIR, BACKUP_DIR, CERTIFICATES_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
});

const DB_FILE = path.join(DATA_DIR, 'cyphox_db.json');

// Default initial state
const defaultState = {
  users: [],
  operations: [],
  certificates: [],
  jobs: {},
  devices: [],
  deletedFiles: []
};

class Database {
  constructor() {
    this.data = { ...defaultState };
    this.load();
  }

  load() {
    try {
      if (fs.existsSync(DB_FILE)) {
        const raw = fs.readFileSync(DB_FILE, 'utf8');
        this.data = { ...defaultState, ...JSON.parse(raw) };
        if (!Array.isArray(this.data.deletedFiles)) {
          this.data.deletedFiles = [];
        }
      } else {
        this.save();
      }
    } catch (err) {
      console.error('Error loading database, resetting to default:', err);
      this.data = { ...defaultState };
      this.save();
    }
  }

  save() {
    try {
      fs.writeFileSync(DB_FILE, JSON.stringify(this.data, null, 2), 'utf8');
    } catch (err) {
      console.error('Error saving database:', err);
    }
  }

  // User queries
  findUserByEmail(email) {
    if (!email) return null;
    return this.data.users.find(u => u.email.toLowerCase() === email.toLowerCase());
  }

  findUserById(id) {
    return this.data.users.find(u => u.id === id);
  }

  createUser(user) {
    this.data.users.push(user);
    this.save();
    return user;
  }

  // Operation / History queries
  addOperation(operation) {
    const op = {
      id: operation.id || `op_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`,
      timestamp: new Date().toISOString(),
      ...operation
    };
    this.data.operations.unshift(op);
    this.save();
    return op;
  }

  getOperations(userId) {
    if (userId) {
      return this.data.operations.filter(op => op.userId === userId);
    }
    return this.data.operations;
  }

  deleteOperation(id) {
    const index = this.data.operations.findIndex(op => op.id === id);
    if (index !== -1) {
      this.data.operations.splice(index, 1);
      this.save();
      return true;
    }
    return false;
  }

  // Deleted Files Journal & Tracking for Instant File Recovery
  addDeletedFile(fileRecord) {
    if (!this.data.deletedFiles) {
      this.data.deletedFiles = [];
    }
    const record = {
      id: fileRecord.id || `del_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`,
      name: fileRecord.name,
      originalPath: fileRecord.originalPath || '',
      vaultPath: fileRecord.vaultPath || '',
      size: fileRecord.size || 0,
      sizeFormatted: fileRecord.sizeFormatted || '0 B',
      mime: fileRecord.mime || 'application/octet-stream',
      category: fileRecord.category || 'Documents',
      sha256: fileRecord.sha256 || '',
      entropy: fileRecord.entropy || 0.0,
      recoverability: fileRecord.recoverability || 'High',
      status: fileRecord.status || 'DELETED', // DELETED, RECOVERED
      userId: fileRecord.userId || 'guest',
      deletedAt: fileRecord.deletedAt || new Date().toISOString(),
      recoveredAt: null,
      recoveredPath: null
    };

    // Unshift to put newest at index 0 (top)
    this.data.deletedFiles.unshift(record);
    this.save();
    return record;
  }

  getDeletedFiles(userId) {
    if (!this.data.deletedFiles) this.data.deletedFiles = [];
    if (userId && userId !== 'all') {
      return this.data.deletedFiles.filter(f => f.userId === userId || f.userId === 'guest');
    }
    return this.data.deletedFiles;
  }

  getLastDeletedFile(userId) {
    const files = this.getDeletedFiles(userId);
    // Find latest deleted file (regardless of status or currently DELETED first)
    const activeDeleted = files.find(f => f.status === 'DELETED');
    return activeDeleted || files[0] || null;
  }

  getDeletedFileById(id) {
    if (!this.data.deletedFiles) return null;
    return this.data.deletedFiles.find(f => f.id === id);
  }

  updateDeletedFile(id, updates) {
    const file = this.getDeletedFileById(id);
    if (file) {
      Object.assign(file, updates);
      this.save();
      return file;
    }
    return null;
  }

  // Certificate queries
  addCertificate(cert) {
    this.data.certificates.unshift(cert);
    this.save();
    return cert;
  }

  getCertificates(userId) {
    if (userId) {
      return this.data.certificates.filter(c => c.userId === userId);
    }
    return this.data.certificates;
  }

  getCertificateById(id) {
    return this.data.certificates.find(c => c.id === id || c.certificateId === id);
  }

  // Live Job queries
  setJob(jobId, jobData) {
    this.data.jobs[jobId] = {
      ...this.data.jobs[jobId],
      ...jobData,
      updatedAt: new Date().toISOString()
    };
    return this.data.jobs[jobId];
  }

  getJob(jobId) {
    return this.data.jobs[jobId] || null;
  }

  // Stats
  getStats(userId) {
    const userOps = userId ? this.data.operations.filter(op => op.userId === userId) : this.data.operations;
    const completed = userOps.filter(op => op.status === 'COMPLETED').length;
    const pending = userOps.filter(op => op.status === 'RUNNING' || op.status === 'PENDING').length;
    const verified = userOps.filter(op => op.verified === true || op.status === 'VERIFIED').length;
    const deletedCount = (this.data.deletedFiles || []).filter(f => f.status === 'DELETED').length;
    const recoveredCount = (this.data.deletedFiles || []).filter(f => f.status === 'RECOVERED').length;

    return {
      devices: this.data.devices.length || 3,
      completedOps: completed,
      pending: pending,
      verified: verified,
      totalCertificates: this.data.certificates.length,
      deletedFilesCount: deletedCount,
      recoveredFilesCount: recoveredCount
    };
  }
}

const db = new Database();
module.exports = db;

