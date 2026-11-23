-- HyOS D1 schema（设计文档 §11.2）
CREATE TABLE IF NOT EXISTS devices (
  did TEXT PRIMARY KEY,
  dk_pub TEXT NOT NULL,            -- hex 32B
  tk_master TEXT NOT NULL,         -- hex 32B（信封主密钥）
  wk0_root TEXT NOT NULL,          -- hex 32B
  wk1_root TEXT NOT NULL,          -- hex 32B
  dek_sys TEXT NOT NULL,           -- hex 32B
  dek_app TEXT NOT NULL,           -- hex 32B
  grub_ver_max INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'provisioned',  -- provisioned|active|quarantine|revoked
  created_at INTEGER NOT NULL,
  activated_at INTEGER
);

CREATE TABLE IF NOT EXISTS epochs (
  did TEXT NOT NULL,
  epoch INTEGER NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending',       -- pending|grub_ok|sys_ok|app_ok|sealed
  last_acked_epoch INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  sealed_at INTEGER,
  PRIMARY KEY (did, epoch)
);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  did TEXT, stage TEXT, epoch INTEGER,
  ip TEXT, ts INTEGER NOT NULL, evidence TEXT
);

CREATE TABLE IF NOT EXISTS config_tokens (
  jti TEXT PRIMARY KEY, did TEXT, commit_hash TEXT, exp INTEGER
);
