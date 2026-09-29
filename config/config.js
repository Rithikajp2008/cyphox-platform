const path = require('path');
const os = require('os');

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'cyphox_super_secure_forensic_jwt_secret_2026_key!';
const DATA_DIR = path.join(__dirname, '..', 'data');
const STORAGE_DIR = path.join(DATA_DIR, 'storage');
const RECOVERED_DIR = path.join(DATA_DIR, 'recovered');
const DELETED_VAULT_DIR = path.join(DATA_DIR, 'deleted_vault');
const BACKUP_DIR = path.join(DATA_DIR, 'backups');
const CERTIFICATES_DIR = path.join(DATA_DIR, 'certificates');

module.exports = {
  PORT,
  JWT_SECRET,
  DATA_DIR,
  STORAGE_DIR,
  RECOVERED_DIR,
  DELETED_VAULT_DIR,
  BACKUP_DIR,
  CERTIFICATES_DIR,
  OS_PLATFORM: os.platform(),
  IS_WINDOWS: os.platform() === 'win32'
};

