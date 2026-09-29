const fs = require('fs');
const path = require('path');

// In-memory & persisted journal of real-time deletion events
const JOURNAL_FILE = path.join(__dirname, '..', 'data', 'realtime_deletion_journal.json');

class DriveWatcher {
  constructor() {
    this.watchers = new Map();
    this.journal = this.loadJournal();
    this.snapshots = new Map();
  }

  loadJournal() {
    try {
      if (fs.existsSync(JOURNAL_FILE)) {
        return JSON.parse(fs.readFileSync(JOURNAL_FILE, 'utf8'));
      }
    } catch (e) {}
    return [];
  }

  saveJournal() {
    try {
      const dir = path.dirname(JOURNAL_FILE);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(JOURNAL_FILE, JSON.stringify(this.journal.slice(-100), null, 2));
    } catch (e) {}
  }

  // Record a real-time deletion event with exact millisecond timestamp
  recordDeletion(filePath, fileInfo = {}) {
    const entry = {
      path: filePath,
      name: path.basename(filePath),
      parentDir: path.basename(path.dirname(filePath)),
      deletedAt: new Date().toISOString(),
      timestamp: Date.now(),
      size: fileInfo.size || 0,
      ...fileInfo
    };

    // Prepend (newest first)
    this.journal.unshift(entry);
    this.saveJournal();
    console.log(`[DriveWatcher] 🎯 Recorded real-time deletion: ${entry.name} at ${entry.deletedAt}`);
    return entry;
  }

  getLastDeleted() {
    return this.journal.length > 0 ? this.journal[0] : null;
  }

  getRecentDeletions(limit = 10) {
    return this.journal.slice(0, limit);
  }

  // Take a baseline snapshot of a drive/directory to detect deletions by diffing
  takeSnapshot(drivePath) {
    if (!fs.existsSync(drivePath)) return;
    try {
      const files = new Map();
      const walk = (dir) => {
        try {
          const list = fs.readdirSync(dir, { withFileTypes: true });
          for (const item of list) {
            const full = path.join(dir, item.name);
            if (item.isDirectory() && !item.name.startsWith('$') && !item.name.includes('System Volume')) {
              walk(full);
            } else if (item.isFile()) {
              try {
                const s = fs.statSync(full);
                files.set(full, { size: s.size, mtimeMs: s.mtimeMs });
              } catch (e) {}
            }
          }
        } catch (e) {}
      };

      walk(drivePath);
      this.snapshots.set(drivePath, files);
    } catch (e) {}
  }

  // Diff current state against baseline to find which file disappeared
  detectDeletedFromSnapshot(drivePath) {
    const baseline = this.snapshots.get(drivePath);
    if (!baseline || !fs.existsSync(drivePath)) return [];

    const disappeared = [];
    for (const [filePath, info] of baseline.entries()) {
      if (!fs.existsSync(filePath)) {
        disappeared.push({
          path: filePath,
          name: path.basename(filePath),
          parentDir: path.basename(path.dirname(filePath)),
          size: info.size,
          deletedAt: new Date().toISOString(),
          timestamp: Date.now()
        });
      }
    }
    return disappeared;
  }
}

module.exports = new DriveWatcher();
