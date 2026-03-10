require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const https = require('https');
const RSSParser = require('rss-parser');
const snmp = require('net-snmp');
const { Client: SSHClient } = require('ssh2');
const FortiGateParser = require('./fortigate-parser');
const SwitchParser = require('./switch-parser');

const app = express();
// ... rest of initial declarations

// SNMP Utility Function
const checkSnmpStatus = (target, config) => {
  return new Promise((resolve) => {
    try {
      let session;
      const options = {
        port: 161,
        retries: 1,
        timeout: 2000,
        transport: "udp4",
        trapPort: 162,
        version: config.version === 'v3' ? snmp.Version3 : snmp.Version2c
      };

      if (config.version === 'v3') {
        const user = {
          name: config.security_name,
          level: snmp.SecurityLevel[config.security_level] || snmp.SecurityLevel.noAuthNoPriv
        };
        
        if (user.level >= snmp.SecurityLevel.authNoPriv) {
          user.authProtocol = snmp.AuthProtocols[config.auth_protocol.toLowerCase()] || snmp.AuthProtocols.sha;
          user.authKey = config.auth_key;
        }
        
        if (user.level >= snmp.SecurityLevel.authPriv) {
          user.privProtocol = snmp.PrivProtocols[config.priv_protocol.toLowerCase()] || snmp.PrivProtocols.aes;
          user.privKey = config.priv_key;
        }
        
        session = snmp.createV3Session(target, user, options);
      } else {
        session = snmp.createSession(target, config.community || 'public', options);
      }

      // sysName.0 OID
      const oids = ["1.3.6.1.2.1.1.5.0"];

      session.get(oids, (error, varbinds) => {
        if (error) {
          session.close();
          resolve({ status: 'offline', error: error.message });
        } else {
          const sysName = varbinds[0].value.toString();
          session.close();
          resolve({ status: 'online', sysName });
        }
      });
    } catch (err) {
      resolve({ status: 'offline', error: err.message });
    }
  });
};

// ... inside app.js (after middleware)
const PORT = process.env.PORT || 5000;
const rssParser = new RSSParser();
const DEFAULT_CVE_SYNC_MINUTES = 60;
let cveSyncIntervalMs = DEFAULT_CVE_SYNC_MINUTES * 60 * 1000;
let cveSyncTimer = null;

// Middleware
app.use(cors({ origin: '*' }));
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));

// DB Connection
const pool = new Pool({
  user: process.env.DB_USER || 'nssuser',
  password: process.env.DB_PASSWORD || 'nsspass123',
  host: process.env.DB_HOST || 'db',
  port: process.env.DB_PORT || 5432,
  database: process.env.DB_NAME || 'network_security_db'
});

let isDbReady = false;
let securityKB = [];
const KB_METADATA_PATH = path.join(__dirname, 'data', 'security_kb_metadata.json');
const KB_LEGACY_PATH = path.join(__dirname, 'data', 'security_kb.json');
const SWITCH_KB_METADATA_PATH = path.join(__dirname, 'data', 'switch_security_kb_metadata.json');

const readJsonArrayFile = (filePath) => {
  if (!fs.existsSync(filePath)) return [];
  const raw = fs.readFileSync(filePath, 'utf-8');
  const parsed = JSON.parse(raw);
  return Array.isArray(parsed) ? parsed : [];
};

const writeJsonArrayFile = (filePath, data) => {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf-8');
};

const allowedCveFetchMethods = new Set([
  'fortiguard_rss',
  'nvd_api',
  'cisa_kev_json',
  'zdi_rss',
  'generic_rss',
  'generic_json'
]);

const defaultCveSources = [
  {
    source_key: 'fortiguard',
    name: 'FortiGuard PSIRT RSS',
    url: 'https://www.fortiguard.com/rss/ir.xml',
    fetch_method: 'fortiguard_rss',
    keyword: 'fortinet',
    enabled: true,
    config: {}
  },
  {
    source_key: 'nvd',
    name: 'NVD API (Fortinet keyword)',
    url: 'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=fortinet&resultsPerPage=100',
    fetch_method: 'nvd_api',
    keyword: 'fortinet',
    enabled: true,
    config: {}
  },
  {
    source_key: 'cisa-kev',
    name: 'CISA KEV JSON',
    url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    fetch_method: 'cisa_kev_json',
    keyword: 'fortinet',
    enabled: true,
    config: {}
  },
  {
    source_key: 'zdi',
    name: 'ZDI RSS',
    url: 'https://www.zerodayinitiative.com/rss/published/',
    fetch_method: 'zdi_rss',
    keyword: 'fortinet',
    enabled: true,
    config: {}
  }
];

// Database Init
const initDB = async () => {
  try {
    await pool.query('SELECT NOW()');
    console.log('✓ DB Bağlantısı OK');
    isDbReady = true;

    // ... (Existing tables: devices, security_rules, settings, uploaded_files)
    await pool.query(`CREATE TABLE IF NOT EXISTS snmp_templates (
      id SERIAL PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      version VARCHAR(10) NOT NULL,
      community VARCHAR(255),
      security_name VARCHAR(255),
      security_level VARCHAR(50),
      auth_protocol VARCHAR(20),
      auth_key VARCHAR(255),
      priv_protocol VARCHAR(20),
      priv_key VARCHAR(255),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS ssh_templates (
      id SERIAL PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      username VARCHAR(255) NOT NULL,
      password VARCHAR(255) NOT NULL,
      port INTEGER DEFAULT 22,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS api_templates (
      id SERIAL PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      base_url VARCHAR(255) NOT NULL,
      api_key VARCHAR(255),
      auth_type VARCHAR(50) DEFAULT 'Bearer',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS network_scans (
      id SERIAL PRIMARY KEY,
      ip_range VARCHAR(255) NOT NULL,
      snmp_template_ids INTEGER[] NOT NULL,
      status VARCHAR(50) DEFAULT 'idle',
      progress_current INTEGER DEFAULT 0,
      progress_total INTEGER DEFAULT 0,
      discovered_count INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    // Ensure columns exist (for existing tables)
    await pool.query(`ALTER TABLE network_scans ADD COLUMN IF NOT EXISTS discovered_count INTEGER DEFAULT 0`);
    await pool.query(`ALTER TABLE network_scans ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP`);

    await pool.query(`CREATE TABLE IF NOT EXISTS discovered_devices (
      id SERIAL PRIMARY KEY,
      scan_id INTEGER REFERENCES network_scans(id) ON DELETE CASCADE,
      ip_address VARCHAR(255) NOT NULL,
      hostname VARCHAR(255),
      snmp_template_id INTEGER REFERENCES snmp_templates(id),
      status VARCHAR(50) DEFAULT 'discovered', -- 'discovered', 'added'
      discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS topologies (
      id SERIAL PRIMARY KEY,
      name VARCHAR(255) DEFAULT 'Main Topology',
      nodes JSONB DEFAULT '[]',
      edges JSONB DEFAULT '[]',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS custom_icons (
      id SERIAL PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      data TEXT NOT NULL, -- base64 data
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS devices (
      id SERIAL PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      ip_address VARCHAR(255) NOT NULL UNIQUE,
      api_key TEXT,
      vdom VARCHAR(100) DEFAULT 'root',
      connection_method VARCHAR(50) DEFAULT 'snmp_ssh', -- 'api' or 'snmp_ssh'
      snmp_template_id INTEGER REFERENCES snmp_templates(id) ON DELETE SET NULL,
      ssh_template_id INTEGER REFERENCES ssh_templates(id) ON DELETE SET NULL,
      api_template_id INTEGER REFERENCES api_templates(id) ON DELETE SET NULL,
      manual_snmp_config JSONB,
      status VARCHAR(50) DEFAULT 'unknown',
      last_sync TIMESTAMP,
      metadata JSONB,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    // Check if columns exist, add if not (for existing databases)
    try {
      const cols = [
        { name: 'connection_method', type: 'VARCHAR(50) DEFAULT \'snmp_ssh\'' },
        { name: 'snmp_template_id', type: 'INTEGER REFERENCES snmp_templates(id) ON DELETE SET NULL' },
        { name: 'ssh_template_id', type: 'INTEGER REFERENCES ssh_templates(id) ON DELETE SET NULL' },
        { name: 'api_template_id', type: 'INTEGER REFERENCES api_templates(id) ON DELETE SET NULL' },
        { name: 'manual_snmp_config', type: 'JSONB' },
        { name: 'metadata', type: 'JSONB' },
        { name: 'vdom', type: 'VARCHAR(100) DEFAULT \'root\'' },
        { name: 'api_key', type: 'TEXT' },
        { name: 'created_at', type: 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP' },
        { name: 'updated_at', type: 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP' }
      ];
      for (const col of cols) {
        await pool.query(`ALTER TABLE devices ADD COLUMN IF NOT EXISTS ${col.name} ${col.type}`);
      }
    } catch (e) { console.log('Migration note:', e.message); }

    await pool.query(`CREATE TABLE IF NOT EXISTS security_rules (
      id VARCHAR(50) PRIMARY KEY,
      category VARCHAR(50),
      severity VARCHAR(50),
      name VARCHAR(255),
      cli_path TEXT,
      check_logic TEXT,
      remediation TEXT,
      eval_path TEXT,
      eval_type VARCHAR(50),
      eval_expected JSONB,
      default_val TEXT,
      is_custom BOOLEAN DEFAULT false,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS switch_security_rules (
      id SERIAL PRIMARY KEY,
      rule_id VARCHAR(120) NOT NULL,
      switch_vendor VARCHAR(120) NOT NULL DEFAULT 'generic',
      switch_model VARCHAR(120) NOT NULL DEFAULT 'all',
      rule_data JSONB NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(rule_id, switch_vendor, switch_model)
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS settings (
      key VARCHAR(100) PRIMARY KEY,
      value JSONB,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS cve_alerts (
      id SERIAL PRIMARY KEY,
      cve_id VARCHAR(100) UNIQUE,
      title TEXT,
      description TEXT,
      severity VARCHAR(50),
      link TEXT,
      solution TEXT,
      published_at TIMESTAMP,
      is_new BOOLEAN DEFAULT true,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS cve_sources (
      id SERIAL PRIMARY KEY,
      source_key VARCHAR(80) UNIQUE,
      name VARCHAR(255) NOT NULL,
      url TEXT NOT NULL,
      fetch_method VARCHAR(50) NOT NULL DEFAULT 'generic_rss',
      keyword VARCHAR(120) DEFAULT 'fortinet',
      enabled BOOLEAN DEFAULT true,
      config JSONB DEFAULT '{}'::jsonb,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS uploaded_files (
      id SERIAL PRIMARY KEY,
      file_uid UUID UNIQUE NOT NULL,
      file_name VARCHAR(255) NOT NULL,
      file_content TEXT,
      file_size INTEGER,
      upload_status VARCHAR(50),
      parse_status VARCHAR(50) DEFAULT 'pending',
      summary_data JSONB,
      analysis_data JSONB,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS device_hit_history (
      id SERIAL PRIMARY KEY,
      device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
      hit_count BIGINT DEFAULT 0,
      policy_count INTEGER DEFAULT 0,
      collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS device_metrics_history (
      id SERIAL PRIMARY KEY,
      device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
      metrics JSONB,
      collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    console.log('✓ Tablolar OK');
    await loadSecurityKB();
    await seedSwitchSecurityKBIfEmpty();
    await seedDefaultSnmpTemplates();
    await ensureDefaultCveSources();
    await loadCveSyncConfig();
    scheduleCveSync();
    // Initial CVE Sync
    syncCVEs();
  } catch (err) { console.error('✗ DB hatası:', err.message); }
};

const ensureDefaultCveSources = async () => {
  for (const source of defaultCveSources) {
    await pool.query(
      `INSERT INTO cve_sources (source_key, name, url, fetch_method, keyword, enabled, config)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (source_key) DO NOTHING`,
      [
        source.source_key,
        source.name,
        source.url,
        source.fetch_method,
        source.keyword,
        source.enabled,
        JSON.stringify(source.config || {})
      ]
    );
  }
};

const loadCveSyncConfig = async () => {
  const row = await pool.query('SELECT value FROM settings WHERE key = $1', ['cve_sync_config']);
  const cfg = row.rows[0]?.value || {};
  const minutes = Number(cfg.interval_minutes || DEFAULT_CVE_SYNC_MINUTES);
  const safeMinutes = Number.isFinite(minutes) ? Math.max(5, Math.min(1440, minutes)) : DEFAULT_CVE_SYNC_MINUTES;
  cveSyncIntervalMs = safeMinutes * 60 * 1000;
  return { interval_minutes: safeMinutes };
};

const scheduleCveSync = () => {
  if (cveSyncTimer) clearInterval(cveSyncTimer);
  cveSyncTimer = setInterval(syncCVEs, cveSyncIntervalMs);
  console.log(`✓ CVE otomatik tarama periyodu: ${Math.round(cveSyncIntervalMs / 60000)} dakika`);
};

const cvssScoreToSeverity = (score) => {
  const n = Number(score);
  if (Number.isNaN(n)) return 'MEDIUM';
  if (n >= 9.0) return 'CRITICAL';
  if (n >= 7.0) return 'HIGH';
  if (n >= 4.0) return 'MEDIUM';
  return 'LOW';
};

const inferSeverityFromText = (text) => {
  const t = String(text || '').toLowerCase();
  if (t.includes('critical')) return 'CRITICAL';
  if (t.includes('high')) return 'HIGH';
  if (t.includes('medium')) return 'MEDIUM';
  if (t.includes('low')) return 'LOW';
  return 'MEDIUM';
};

const extractCveIds = (text) => {
  const matches = String(text || '').match(/CVE-\d{4}-\d{4,7}/gi) || [];
  return [...new Set(matches.map((m) => m.toUpperCase()))];
};

const hashString = (input) => {
  let hash = 0;
  const str = String(input || '');
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash) + str.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash);
};

const stableAdvisoryId = (source, title) => `${source}-${hashString(title).toString(36)}`;

const getByPath = (obj, pathExpr) => {
  if (!pathExpr) return undefined;
  return String(pathExpr)
    .split('.')
    .reduce((acc, segment) => (acc && typeof acc === 'object' ? acc[segment] : undefined), obj);
};

const insertCveIfMissing = async ({ cveId, title, description, severity, link, solution, publishedAt }) => {
  if (!title) return false;
  const resolvedId = cveId || stableAdvisoryId('ADV', title);
  const check = await pool.query('SELECT id FROM cve_alerts WHERE cve_id = $1 OR title = $2', [resolvedId, title]);
  if (check.rows.length > 0) return false;

  await pool.query(
    'INSERT INTO cve_alerts (cve_id, title, description, severity, link, solution, published_at) VALUES ($1, $2, $3, $4, $5, $6, $7)',
    [resolvedId, title, description || '', severity || 'MEDIUM', link || null, solution || null, publishedAt || new Date().toISOString()]
  );
  return true;
};

const collectFortiGuardCves = async (source) => {
  let newCount = 0;
  const feedUrl = source?.url || 'https://www.fortiguard.com/rss/ir.xml';
  const feed = await rssParser.parseURL(feedUrl);

  for (const item of feed.items || []) {
    const title = item.title || 'Fortinet PSIRT Advisory';
    const description = item.contentSnippet || item.content || '';
    const link = item.link || 'https://www.fortiguard.com/psirt';
    const publishedAt = item.pubDate || new Date().toISOString();
    const severity = inferSeverityFromText(`${title} ${description}`);
    const ids = extractCveIds(`${title} ${description}`);
    // Extract solution if available from description
    const solution = description.match(/solution|patch|update|fix|remediation|mitigation/i) 
      ? description.split(/solution|patch|update|fix|remediation|mitigation/i).slice(1).join(' ').trim().slice(0, 500) 
      : null;

    if (ids.length === 0) {
      const added = await insertCveIfMissing({
        cveId: stableAdvisoryId('FG-IR', title),
        title,
        description,
        severity,
        link,
        solution,
        publishedAt
      });
      if (added) newCount++;
      continue;
    }

    for (const id of ids) {
      const added = await insertCveIfMissing({ cveId: id, title, description, severity, link, solution, publishedAt });
      if (added) newCount++;
    }
  }

  return newCount;
};

const collectNvdCves = async (source) => {
  let newCount = 0;
  const url = source?.url || 'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=fortinet&resultsPerPage=100';
  const response = await axios.get(url, { timeout: 20000 });
  const items = response?.data?.vulnerabilities || [];

  for (const item of items) {
    const cve = item?.cve || {};
    const cveId = cve?.id;
    if (!cveId) continue;

    const descObj = (cve.descriptions || []).find((d) => d.lang === 'en') || cve.descriptions?.[0];
    const description = descObj?.value || '';
    const title = `${cveId} - ${description.slice(0, 140)}`;

    const metrics = cve.metrics || {};
    const baseScore = metrics.cvssMetricV31?.[0]?.cvssData?.baseScore
      ?? metrics.cvssMetricV30?.[0]?.cvssData?.baseScore
      ?? metrics.cvssMetricV2?.[0]?.cvssData?.baseScore;

    const severity = cvssScoreToSeverity(baseScore);
    const link = `https://nvd.nist.gov/vuln/detail/${cveId}`;
    const publishedAt = cve.published || new Date().toISOString();
    
    // Extract solution info from references or configurations
    const references = cve.references || [];
    const patchRef = references.find(r => r.tags?.includes('Patch') || r.tags?.includes('Vendor Advisory'));
    const solution = patchRef ? `Patch available: ${patchRef.url}` : null;

    const added = await insertCveIfMissing({ cveId, title, description, severity, link, solution, publishedAt });
    if (added) newCount++;
  }

  return newCount;
};

const collectCisaKevCves = async (source) => {
  let newCount = 0;
  const url = source?.url || 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
  const response = await axios.get(url, { timeout: 20000 });
  const items = response?.data?.vulnerabilities || [];
  const fortinetItems = items.filter((v) => String(v.vendorProject || '').toLowerCase().includes('fortinet'));

  for (const v of fortinetItems) {
    const cveId = String(v.cveID || '').toUpperCase();
    if (!cveId) continue;
    const title = `${cveId} - ${v.vendorProject || 'Fortinet'} ${v.product || ''}`.trim();
    const description = v.shortDescription || '';
    const solution = v.requiredAction || 'Refer to vendor advisory for mitigation steps.';
    const severity = v.knownRansomwareCampaignUse === 'Known' ? 'CRITICAL' : 'HIGH';
    const link = `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(cveId)}`;
    const publishedAt = v.dateAdded || new Date().toISOString();

    const added = await insertCveIfMissing({ cveId, title, description, severity, link, solution, publishedAt });
    if (added) newCount++;
  }

  return newCount;
};

const collectZdiFortinetCves = async (source) => {
  let newCount = 0;
  const feedUrl = source?.url || 'https://www.zerodayinitiative.com/rss/published/';
  const feed = await rssParser.parseURL(feedUrl);
  const keyword = String(source?.keyword || 'fortinet').toLowerCase();

  for (const item of feed.items || []) {
    const title = item.title || 'ZDI Advisory';
    const description = item.contentSnippet || item.content || '';
    const fullText = `${title} ${description}`;
    if (keyword && !fullText.toLowerCase().includes(keyword)) continue;

    const link = item.link || 'https://www.zerodayinitiative.com/advisories/';
    const publishedAt = item.pubDate || new Date().toISOString();
    const severity = inferSeverityFromText(fullText);
    const ids = extractCveIds(fullText);
    const solution = description.match(/workaround|mitigation|patch|update/i) 
      ? description.split(/workaround|mitigation|patch|update/i).slice(1).join(' ').trim().slice(0, 500) 
      : null;

    if (ids.length === 0) {
      const added = await insertCveIfMissing({
        cveId: stableAdvisoryId('ZDI', title),
        title,
        description,
        severity,
        link,
        solution,
        publishedAt
      });
      if (added) newCount++;
      continue;
    }

    for (const id of ids) {
      const added = await insertCveIfMissing({ cveId: id, title, description, severity, link, solution, publishedAt });
      if (added) newCount++;
    }
  }

  return newCount;
};

const collectGenericRssCves = async (source) => {
  let newCount = 0;
  const feed = await rssParser.parseURL(source.url);
  const keyword = String(source.keyword || '').toLowerCase();

  for (const item of feed.items || []) {
    const title = item.title || source.name || 'RSS Advisory';
    const description = item.contentSnippet || item.content || '';
    const fullText = `${title} ${description}`;
    if (keyword && !fullText.toLowerCase().includes(keyword)) continue;

    const link = item.link || source.url;
    const publishedAt = item.pubDate || new Date().toISOString();
    const severity = inferSeverityFromText(fullText);
    const ids = extractCveIds(fullText);
    const solution = description.match(/solution|patch|update|fix|remediation/i) 
      ? description.split(/solution|patch|update|fix|remediation/i).slice(1).join(' ').trim().slice(0, 500) 
      : null;

    if (ids.length === 0) {
      const added = await insertCveIfMissing({
        cveId: stableAdvisoryId(`RSS-${source.id}`, title),
        title,
        description,
        severity,
        link,
        solution,
        publishedAt
      });
      if (added) newCount++;
      continue;
    }

    for (const id of ids) {
      const added = await insertCveIfMissing({ cveId: id, title, description, severity, link, solution, publishedAt });
      if (added) newCount++;
    }
  }

  return newCount;
};

const collectGenericJsonCves = async (source) => {
  let newCount = 0;
  const cfg = source.config || {};
  const response = await axios.get(source.url, { timeout: 20000 });
  const data = response?.data;

  const itemsPath = cfg.itemsPath || 'vulnerabilities';
  const list = Array.isArray(data)
    ? data
    : (getByPath(data, itemsPath) || getByPath(data, 'items') || []);

  const items = Array.isArray(list) ? list : [];
  const keyword = String(source.keyword || '').toLowerCase();
  const cveIdField = cfg.cveIdField || 'cveID';
  const titleField = cfg.titleField || 'title';
  const descriptionField = cfg.descriptionField || 'shortDescription';
  const severityField = cfg.severityField || 'severity';
  const linkField = cfg.linkField || 'link';
  const publishedField = cfg.publishedField || 'published';
  const solutionField = cfg.solutionField || 'requiredAction';

  for (const item of items) {
    const title = getByPath(item, titleField) || 'JSON CVE Advisory';
    const description = getByPath(item, descriptionField) || '';
    const fullText = `${title} ${description}`;
    if (keyword && !fullText.toLowerCase().includes(keyword)) continue;

    const cveId = String(getByPath(item, cveIdField) || '').toUpperCase();
    const severityRaw = getByPath(item, severityField) || '';
    const severity = inferSeverityFromText(severityRaw);
    const link = getByPath(item, linkField) || source.url;
    const publishedAt = getByPath(item, publishedField) || new Date().toISOString();
    const solution = getByPath(item, solutionField) || null;

    if (cveId && cveId.startsWith('CVE-')) {
      const added = await insertCveIfMissing({ cveId, title, description, severity, link, solution, publishedAt });
      if (added) newCount++;
      continue;
    }

    const ids = extractCveIds(fullText);
    if (ids.length === 0) {
      const added = await insertCveIfMissing({
        cveId: stableAdvisoryId(`JSON-${source.id}`, title),
        title,
        description,
        severity,
        link,
        solution,
        publishedAt
      });
      if (added) newCount++;
      continue;
    }

    for (const id of ids) {
      const added = await insertCveIfMissing({ cveId: id, title, description, severity, link, solution, publishedAt });
      if (added) newCount++;
    }
  }

  return newCount;
};

// --- CVE Sync Logic (Multi-source Fortinet tracking) ---
const syncCVEs = async () => {
  try {
    const sourcesRes = await pool.query('SELECT * FROM cve_sources WHERE enabled = true ORDER BY id ASC');
    const enabledSources = sourcesRes.rows;
    if (enabledSources.length === 0) {
      console.log('! CVE tarama atlandi: aktif kaynak yok.');
      return 0;
    }

    console.log(`↻ CVE kaynakları taranıyor (${enabledSources.length} aktif kaynak)...`);

    const collectors = {
      fortiguard_rss: collectFortiGuardCves,
      nvd_api: collectNvdCves,
      cisa_kev_json: collectCisaKevCves,
      zdi_rss: collectZdiFortinetCves,
      generic_rss: collectGenericRssCves,
      generic_json: collectGenericJsonCves
    };

    let totalNew = 0;
    for (const source of enabledSources) {
      try {
        const collector = collectors[source.fetch_method];
        if (!collector) {
          console.error(`! ${source.name} tarama atlandi: bilinmeyen yontem (${source.fetch_method})`);
          continue;
        }
        const added = await collector(source);
        totalNew += added;
        console.log(`✓ ${source.name}: ${added} yeni kayit`);
      } catch (sourceErr) {
        console.error(`! ${source.name} tarama hatasi:`, sourceErr.message);
      }
    }

    console.log(`✓ CVE coklu-kaynak tarama bitti. ${totalNew} yeni acik bulundu.`);
    return totalNew;
  } catch (err) {
    console.error('✗ CVE tarama hatası:', err.message);
    return 0;
  }
};

// --- CVE API Endpoints ---
app.get('/api/cve', async (req, res) => {
  try {
    const requestedLimit = parseInt(req.query.limit, 10);
    const limit = Number.isFinite(requestedLimit) ? Math.min(Math.max(requestedLimit, 1), 1000) : 300;
    const r = await pool.query('SELECT * FROM cve_alerts ORDER BY published_at DESC LIMIT $1', [limit]);
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/cve/unread-count', async (req, res) => {
  try {
    const r = await pool.query('SELECT COUNT(*) FROM cve_alerts WHERE is_new = true');
    res.json({ count: parseInt(r.rows[0].count) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/cve/mark-read', async (req, res) => {
  try {
    await pool.query('UPDATE cve_alerts SET is_new = false');
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/cve/sync', async (req, res) => {
  const newCount = await syncCVEs();
  res.json({ success: true, newCount });
});

app.get('/api/cve/sources', async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM cve_sources ORDER BY id ASC');
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/cve/sources', async (req, res) => {
  try {
    const { name, url, fetch_method, keyword, enabled, config } = req.body;
    if (!name || !url || !fetch_method) {
      return res.status(400).json({ error: 'name, url ve fetch_method zorunludur.' });
    }
    if (!allowedCveFetchMethods.has(fetch_method)) {
      return res.status(400).json({ error: 'Gecersiz fetch_method.' });
    }

    const inserted = await pool.query(
      `INSERT INTO cve_sources (name, url, fetch_method, keyword, enabled, config)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [
        name,
        url,
        fetch_method,
        keyword || 'fortinet',
        enabled !== false,
        JSON.stringify(config || {})
      ]
    );
    res.status(201).json(inserted.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/cve/sources/:id', async (req, res) => {
  try {
    const { name, url, fetch_method, keyword, enabled, config } = req.body;
    if (fetch_method && !allowedCveFetchMethods.has(fetch_method)) {
      return res.status(400).json({ error: 'Gecersiz fetch_method.' });
    }

    const updated = await pool.query(
      `UPDATE cve_sources
       SET name = COALESCE($1, name),
           url = COALESCE($2, url),
           fetch_method = COALESCE($3, fetch_method),
           keyword = COALESCE($4, keyword),
           enabled = COALESCE($5, enabled),
           config = COALESCE($6, config),
           updated_at = NOW()
       WHERE id = $7
       RETURNING *`,
      [
        name,
        url,
        fetch_method,
        keyword,
        typeof enabled === 'boolean' ? enabled : null,
        config ? JSON.stringify(config) : null,
        req.params.id
      ]
    );

    if (updated.rows.length === 0) return res.status(404).json({ error: 'Kaynak bulunamadi.' });
    res.json(updated.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/cve/sources/:id', async (req, res) => {
  try {
    const deleted = await pool.query('DELETE FROM cve_sources WHERE id = $1 RETURNING id', [req.params.id]);
    if (deleted.rows.length === 0) return res.status(404).json({ error: 'Kaynak bulunamadi.' });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/cve/sync-config', async (req, res) => {
  try {
    const cfg = await loadCveSyncConfig();
    res.json(cfg);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/cve/sync-config', async (req, res) => {
  try {
    const minutesRaw = Number(req.body?.interval_minutes);
    const intervalMinutes = Number.isFinite(minutesRaw) ? Math.max(5, Math.min(1440, minutesRaw)) : DEFAULT_CVE_SYNC_MINUTES;

    await pool.query(
      `INSERT INTO settings (key, value, updated_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()`,
      ['cve_sync_config', JSON.stringify({ interval_minutes: intervalMinutes })]
    );

    cveSyncIntervalMs = intervalMinutes * 60 * 1000;
    scheduleCveSync();
    res.json({ success: true, interval_minutes: intervalMinutes });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- Settings & KB Endpoints (Keep previous logic) ---
app.get('/api/settings/ldap', async (req, res) => {
  try {
    const r = await pool.query('SELECT value FROM settings WHERE key = $1', ['ldap_config']);
    res.json(r.rows[0]?.value || {});
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/settings/ldap', async (req, res) => {
  try {
    await pool.query('INSERT INTO settings (key, value, updated_at) VALUES ($1, $2, NOW()) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()', ['ldap_config', JSON.stringify(req.body)]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/settings/certs', async (req, res) => {
  try {
    const r = await pool.query('SELECT value FROM settings WHERE key = $1', ['certs_config']);
    const certs = r.rows[0]?.value;
    res.json(Array.isArray(certs) ? certs : []);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/settings/certs', async (req, res) => {
  try {
    const certs = Array.isArray(req.body) ? req.body : [];
    await pool.query(
      'INSERT INTO settings (key, value, updated_at) VALUES ($1, $2, NOW()) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()',
      ['certs_config', JSON.stringify(certs)]
    );
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/security-kb', async (req, res) => {
  try {
    const kb = fs.existsSync(KB_METADATA_PATH)
      ? readJsonArrayFile(KB_METADATA_PATH)
      : readJsonArrayFile(KB_LEGACY_PATH);
    res.json(kb);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/security-kb', async (req, res) => {
  try {
    const rule = req.body;
    if (!rule?.id) return res.status(400).json({ error: 'Kural id zorunludur.' });

    const sourcePath = fs.existsSync(KB_METADATA_PATH) ? KB_METADATA_PATH : KB_LEGACY_PATH;
    const kb = readJsonArrayFile(sourcePath);
    const idx = kb.findIndex((r) => String(r.id) === String(rule.id));
    if (idx >= 0) kb[idx] = { ...kb[idx], ...rule };
    else kb.push(rule);
    writeJsonArrayFile(sourcePath, kb);

    await loadSecurityKB();
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/security-kb/:id', async (req, res) => {
  try {
    const sourcePath = fs.existsSync(KB_METADATA_PATH) ? KB_METADATA_PATH : KB_LEGACY_PATH;
    const kb = readJsonArrayFile(sourcePath);
    const before = kb.length;
    const filtered = kb.filter((r) => String(r.id) !== String(req.params.id));
    if (filtered.length === before) return res.status(404).json({ error: 'Kural bulunamadi.' });
    writeJsonArrayFile(sourcePath, filtered);
    await loadSecurityKB();
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/switch-security-kb', async (req, res) => {
  try {
    const vendor = String(req.query.vendor || '').trim();
    const model = String(req.query.model || '').trim();

    let sql = 'SELECT rule_id, switch_vendor, switch_model, rule_data FROM switch_security_rules';
    const params = [];
    const where = [];

    if (vendor) {
      params.push(vendor, 'generic');
      where.push(`(switch_vendor = $${params.length - 1} OR switch_vendor = $${params.length})`);
    }

    if (model) {
      params.push(model, 'all');
      where.push(`(switch_model = $${params.length - 1} OR switch_model = $${params.length})`);
    }

    if (where.length > 0) sql += ` WHERE ${where.join(' AND ')}`;
    sql += ' ORDER BY switch_vendor ASC, switch_model ASC, rule_id ASC';

    const rows = await pool.query(sql, params);
    const kb = rows.rows.map((r) => ({
      ...(r.rule_data || {}),
      id: r.rule_id,
      switch_vendor: r.switch_vendor,
      switch_model: r.switch_model
    }));
    res.json(kb);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/switch-security-kb', async (req, res) => {
  try {
    const rule = req.body;
    if (!rule?.id) return res.status(400).json({ error: 'Kural id zorunludur.' });

    const switchVendor = String(rule.switch_vendor || 'generic').trim() || 'generic';
    const switchModel = String(rule.switch_model || 'all').trim() || 'all';

    await pool.query(
      `INSERT INTO switch_security_rules (rule_id, switch_vendor, switch_model, rule_data, updated_at)
       VALUES ($1, $2, $3, $4, NOW())
       ON CONFLICT (rule_id, switch_vendor, switch_model)
       DO UPDATE SET rule_data = EXCLUDED.rule_data, updated_at = NOW()`,
      [
        String(rule.id),
        switchVendor,
        switchModel,
        JSON.stringify({ ...rule, switch_vendor: switchVendor, switch_model: switchModel })
      ]
    );

    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/switch-security-kb/:id', async (req, res) => {
  try {
    const vendor = String(req.query.vendor || '').trim() || 'generic';
    const model = String(req.query.model || '').trim() || 'all';

    const deleted = await pool.query(
      'DELETE FROM switch_security_rules WHERE rule_id = $1 AND switch_vendor = $2 AND switch_model = $3 RETURNING id',
      [String(req.params.id), vendor, model]
    );
    if (deleted.rows.length === 0) return res.status(404).json({ error: 'Kural bulunamadi.' });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

const getFGT = async (ip, key) => {
  try {
    const url = `https://${ip}/api/v2/monitor/system/status?access_token=${key}`;
    const res = await axios.get(url, { timeout: 3000, httpsAgent: new https.Agent({ rejectUnauthorized: false }) });
    let hostname = res.data?.results?.hostname || 'FGT';
    // Clean up invalid hostname patterns (like translate.goog artifacts)
    if (hostname && (hostname.includes('translate.goog') || hostname.includes('\\.translate\\.') || hostname.startsWith('.*'))) {
      hostname = 'FortiGate-Device';
    }
    return { success: true, host: hostname, status: 'online' };
  } catch (e) { return { success: false, status: 'offline' }; }
};

const fetchFGTConfig = async (ip, key) => {
  const httpsAgent = new https.Agent({ rejectUnauthorized: false });
  const endpoints = [
    `https://${ip}/api/v2/monitor/system/config/backup?scope=global&access_token=${key}`,
    `https://${ip}/api/v2/monitor/system/config/backup?access_token=${key}`
  ];

  const errors = [];
  for (const url of endpoints) {
    try {
      const response = await axios.get(url, {
        timeout: 20000,
        httpsAgent,
        responseType: 'text'
      });

      const body = response?.data;
      if (typeof body === 'string' && body.trim().length > 0) return body;

      if (body && typeof body === 'object') {
        const possible = body.results || body.result || body.config || body.data;
        if (typeof possible === 'string' && possible.trim().length > 0) return possible;
      }
    } catch (err) {
      const statusCode = err.response?.status;
      const errorMsg = err.response?.data?.error || err.message;
      errors.push({ endpoint: url.replace(key, '***'), status: statusCode, error: errorMsg });
    }
  }

  // Provide detailed error message
  const errorDetails = errors.map(e => `${e.endpoint} - Status: ${e.status || 'timeout'}`).join('; ');
  throw new Error(`FortiGate config yedegi alinamadi. API token'in 'sysgrp.cfg.read' yetkisi olmayabilir. Detaylar: ${errorDetails}`);
};

// Monitor all devices
app.get('/api/devices/monitor', async (req, res) => {
  try {
    const devs = await pool.query('SELECT * FROM devices');
    const results = [];
    
    for (const dev of devs.rows) {
      const info = await getFGT(dev.ip_address, dev.api_key);
      await pool.query('UPDATE devices SET status = $1, last_sync = NOW() WHERE id = $2', [info.status, dev.id]);
      results.push({ id: dev.id, name: dev.name, status: info.status });
    }
    
    res.json(results);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Scan device config via API
app.post('/api/devices/:id/scan-config', async (req, res) => {
  try {
    const dev = await pool.query('SELECT * FROM devices WHERE id = $1', [req.params.id]);
    if (dev.rows.length === 0) return res.status(404).json({ error: 'Cihaz bulunamadi.' });

    const device = dev.rows[0];
    
    // Önce cihazın durumunu kontrol et
    const deviceStatus = await getFGT(device.ip_address, device.api_key);
    if (!deviceStatus.success || deviceStatus.status === 'offline') {
      return res.status(503).json({ 
        error: 'Cihaz şu anda offline durumda. Config çekmek için cihazın online olması gerekiyor.',
        deviceStatus: 'offline'
      });
    }

    const configContent = await fetchFGTConfig(device.ip_address, device.api_key);
    const uid = uuidv4();
    const fileName = `${device.name || device.ip_address}-api-config-${new Date().toISOString().replace(/[:.]/g, '-')}.conf`;

    // Store device metadata for later use in parsing
    const metadata = JSON.stringify({ device_id: device.id, device_name: device.name });

    await pool.query(
      'INSERT INTO uploaded_files (file_uid, file_name, file_content, file_size, upload_status, config_metadata) VALUES ($1, $2, $3, $4, $5, $6)',
      [uid, fileName, configContent, Buffer.byteLength(configContent, 'utf-8'), 'api_collected', metadata]
    );

    res.json({ success: true, fileUid: uid, deviceId: device.id, fileName });
  } catch (e) {
    console.error('❌ /api/devices/:id/scan-config HATA:', e.message);
    
    // Check if it's a permission error
    if (e.message.includes('sysgrp.cfg.read')) {
      return res.status(403).json({ 
        error: 'API token yetkisi yetersiz',
        details: e.message,
        suggestion: 'FortiGate üzerinde API token için sysgrp.cfg.read yetkisi ekleyin veya config dosyasını manuel olarak yükleyin.'
      });
    }
    
    res.status(500).json({ error: e.message });
  }
});

// Collect policy hit count snapshot for a device.
app.post('/api/devices/:id/fetch-hits', async (req, res) => {
  try {
    const dev = await pool.query('SELECT * FROM devices WHERE id = $1', [req.params.id]);
    if (dev.rows.length === 0) return res.status(404).json({ error: 'Cihaz bulunamadi.' });

    const device = dev.rows[0];
    const deviceStatus = await getFGT(device.ip_address, device.api_key);
    if (!deviceStatus.success || deviceStatus.status === 'offline') {
      return res.json({
        success: true,
        skipped: true,
        reason: 'device_offline',
        deviceId: device.id
      });
    }

    const url = `https://${device.ip_address}/api/v2/monitor/firewall/policy/select/?access_token=${device.api_key}`;
    const response = await axios.get(url, {
      timeout: 12000,
      httpsAgent: new https.Agent({ rejectUnauthorized: false })
    });

    const policies = response?.data?.results;
    const totalPolicies = Array.isArray(policies) ? policies.length : 0;
    const totalHits = Array.isArray(policies)
      ? policies.reduce((sum, p) => sum + (Number(p.hit_count) || 0), 0)
      : 0;

    await pool.query('UPDATE devices SET last_sync = NOW() WHERE id = $1', [device.id]);
    await pool.query(
      'INSERT INTO device_hit_history (device_id, hit_count, policy_count, collected_at) VALUES ($1, $2, $3, NOW())',
      [device.id, totalHits, totalPolicies]
    );

    res.json({
      success: true,
      deviceId: device.id,
      totalPolicies,
      totalHits,
      collectedAt: new Date().toISOString()
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Collect lightweight runtime metrics for a device.
app.post('/api/devices/:id/collect-metrics', async (req, res) => {
  try {
    const dev = await pool.query('SELECT * FROM devices WHERE id = $1', [req.params.id]);
    if (dev.rows.length === 0) return res.status(404).json({ error: 'Cihaz bulunamadi.' });

    const device = dev.rows[0];
    const deviceStatus = await getFGT(device.ip_address, device.api_key);
    if (!deviceStatus.success || deviceStatus.status === 'offline') {
      return res.json({
        success: true,
        skipped: true,
        reason: 'device_offline',
        deviceId: device.id
      });
    }

    const url = `https://${device.ip_address}/api/v2/monitor/system/performance/status?access_token=${device.api_key}`;
    const response = await axios.get(url, {
      timeout: 12000,
      httpsAgent: new https.Agent({ rejectUnauthorized: false })
    });

    const metrics = response?.data?.results || response?.data || {};
    await pool.query('UPDATE devices SET last_sync = NOW() WHERE id = $1', [device.id]);
    await pool.query(
      'INSERT INTO device_metrics_history (device_id, metrics, collected_at) VALUES ($1, $2, NOW())',
      [device.id, JSON.stringify(metrics)]
    );

    res.json({
      success: true,
      deviceId: device.id,
      metrics,
      collectedAt: new Date().toISOString()
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/devices/:id/hit-history', async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT collected_at, hit_count
       FROM device_hit_history
       WHERE device_id = $1
         AND collected_at >= NOW() - INTERVAL '90 days'
       ORDER BY collected_at ASC`,
      [req.params.id]
    );
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/metrics/latest', async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT DISTINCT ON (d.id)
          d.id,
          d.name,
          d.ip_address,
          d.status,
          m.metrics,
          m.collected_at
       FROM devices d
       LEFT JOIN device_metrics_history m ON m.device_id = d.id
       ORDER BY d.id, m.collected_at DESC`
    );
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// File Management
const storage = multer.memoryStorage();
const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024 } });

app.get('/api/uploaded-files', async (req, res) => {
  try {
    const r = await pool.query('SELECT file_uid, file_name, file_size, parse_status, created_at FROM uploaded_files ORDER BY id DESC');
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/switch-scan/file', upload.single('file'), async (req, res) => {
  try {
    const { vendor, model } = req.body;
    if (!req.file) return res.status(400).send('Dosya yok');
    const uid = uuidv4();
    const content = req.file.buffer.toString('utf-8');
    const metadata = JSON.stringify({ vendor, model, config_type: 'switch' });
    await pool.query('INSERT INTO uploaded_files (file_uid, file_name, file_content, file_size, upload_status, config_metadata) VALUES ($1, $2, $3, $4, $5, $6)', [uid, req.file.originalname, content, req.file.size, 'uploaded', metadata]);
    res.json({ fileUid: uid });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/switch-scan/ssh', async (req, res) => {
  const { host, port, username, password, vendor, model } = req.body;
  if (!host || !username || !password || !vendor) {
    return res.status(400).json({ error: 'Eksik bilgiler (host, username, password, vendor zorunludur)' });
  }

  const conn = new SSHClient();
  let configContent = '';

  const command = (vendor === 'huawei') ? 'display current-configuration' : 'show running-config';

  conn.on('ready', () => {
    conn.exec(command, (err, stream) => {
      if (err) {
        conn.end();
        return res.status(500).json({ error: 'SSH Komut Hatasi: ' + err.message });
      }
      stream.on('data', (data) => {
        configContent += data.toString();
      }).on('close', async () => {
        conn.end();
        try {
          const uid = uuidv4();
          const fileName = `${host}-${vendor}-ssh-config.txt`;
          const metadata = JSON.stringify({ vendor, model, config_type: 'switch', host });
          await pool.query('INSERT INTO uploaded_files (file_uid, file_name, file_content, file_size, upload_status, config_metadata) VALUES ($1, $2, $3, $4, $5, $6)', 
            [uid, fileName, configContent, Buffer.byteLength(configContent, 'utf-8'), 'ssh_collected', metadata]);
          res.json({ fileUid: uid });
        } catch (e) {
          res.status(500).json({ error: 'Veritabani Kayit Hatasi: ' + e.message });
        }
      });
    });
  }).on('error', (err) => {
    res.status(500).json({ error: 'SSH Baglanti Hatasi: ' + err.message });
  }).connect({
    host,
    port: port || 22,
    username,
    password,
    readyTimeout: 20000
  });
});

app.post('/api/upload-config', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).send('Dosya yok');
    const uid = uuidv4();
    const content = req.file.buffer.toString('utf-8');
    await pool.query('INSERT INTO uploaded_files (file_uid, file_name, file_content, file_size, upload_status) VALUES ($1, $2, $3, $4, $5)', [uid, req.file.originalname, content, req.file.size, 'uploaded']);
    res.json({ fileUid: uid });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

function detectConfigType(content) {
  if (content.includes('#config-version') || content.includes('config system global')) {
    return 'fortigate';
  }
  // Generic switch detection (Cisco, HP, etc.)
  if (content.toLowerCase().includes('hostname ') && (content.toLowerCase().includes('interface ') || content.toLowerCase().includes('version '))) {
    return 'switch';
  }
  return 'fortigate';
}

app.post('/api/parse-config', async (req, res) => {
  try {
    const { fileUid } = req.body;
    const r = await pool.query('SELECT file_content, config_metadata FROM uploaded_files WHERE file_uid = $1', [fileUid]);
    if (r.rows.length === 0) return res.status(404).send('Dosya yok');
    
    const content = r.rows[0].file_content;
    const configType = detectConfigType(content);
    
    let summaryData, finalData;

    if (configType === 'fortigate') {
      const parser = new FortiGateParser(content);
      parser.parse();
      
      let deviceNameOverride = null;
      if (r.rows[0].config_metadata) {
        try {
          const metadata = JSON.parse(r.rows[0].config_metadata);
          deviceNameOverride = metadata.device_name;
        } catch (e) { /* ignore */ }
      }
      
      summaryData = parser.getSummary(deviceNameOverride);
      const analysis = parser.analyzePolicies(securityKB);
      finalData = { ...analysis, summary: summaryData, config_type: 'fortigate' };
    } else {
      // Switch analysis
      const parser = new SwitchParser(content);
      const deviceInfo = parser.getDeviceInfo();
      
      const rulesRows = await pool.query(
        'SELECT rule_id, rule_data FROM switch_security_rules WHERE switch_vendor = $1 OR switch_vendor = $2',
        [deviceInfo.vendor, 'generic']
      );
      
      const rules = rulesRows.rows.map(row => ({
        ...row.rule_data,
        id: row.rule_id
      }));

      let rulesToUse = rules;
      if (rulesToUse.length === 0) {
        const switchKBMetadata = JSON.parse(fs.readFileSync(path.join(__dirname, 'data', 'switch_security_kb_metadata.json'), 'utf8'));
        rulesToUse = switchKBMetadata;
      }

      const analysis = parser.analyze(rulesToUse);
      summaryData = {
        device_name: deviceInfo.device_name,
        model: deviceInfo.model,
        version: deviceInfo.version,
        vendor: deviceInfo.vendor,
        ...analysis.summary
      };
      finalData = { 
        list: analysis.findings, 
        summary: summaryData, 
        config_type: 'switch' 
      };
    }
    
    await pool.query('UPDATE uploaded_files SET parse_status = $1, summary_data = $2, analysis_data = $3, updated_at = NOW() WHERE file_uid = $4', ['parsed', JSON.stringify(summaryData), JSON.stringify(finalData), fileUid]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/analysis/:fileUid', async (req, res) => {
  try {
    const r = await pool.query('SELECT analysis_data FROM uploaded_files WHERE file_uid = $1', [req.params.fileUid]);
    if (r.rows.length === 0) return res.status(404).send('Analiz bulunamadı');
    res.json(r.rows[0].analysis_data || {});
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/config-detail/:fileUid', async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT file_uid, file_name, parse_status, summary_data, analysis_data, created_at, updated_at
       FROM uploaded_files
       WHERE file_uid = $1`,
      [req.params.fileUid]
    );
    if (r.rows.length === 0) return res.status(404).json({ error: 'Dosya bulunamadi.' });
    res.json({ file: r.rows[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

const loadSecurityKB = async () => {
  try {
    const sourcePath = fs.existsSync(KB_METADATA_PATH) ? KB_METADATA_PATH : KB_LEGACY_PATH;
    securityKB = readJsonArrayFile(sourcePath);
  } catch (err) { console.error('! KB yukleme hatasi:', err.message); }
};

const seedSwitchSecurityKBIfEmpty = async () => {
  try {
    const countRes = await pool.query('SELECT COUNT(*)::int AS count FROM switch_security_rules');
    const count = Number(countRes.rows[0]?.count || 0);
    if (count > 0) return;

    const seed = readJsonArrayFile(SWITCH_KB_METADATA_PATH);
    for (const rule of seed) {
      if (!rule?.id) continue;
      const switchVendor = String(rule.switch_vendor || 'generic').trim() || 'generic';
      const switchModel = String(rule.switch_model || 'all').trim() || 'all';
      await pool.query(
        `INSERT INTO switch_security_rules (rule_id, switch_vendor, switch_model, rule_data, updated_at)
         VALUES ($1, $2, $3, $4, NOW())
         ON CONFLICT (rule_id, switch_vendor, switch_model)
         DO UPDATE SET rule_data = EXCLUDED.rule_data, updated_at = NOW()`,
        [String(rule.id), switchVendor, switchModel, JSON.stringify({ ...rule, switch_vendor: switchVendor, switch_model: switchModel })]
      );
    }
  } catch (err) {
    console.error('! Switch KB seed hatasi:', err.message);
  }
};

const seedDefaultSnmpTemplates = async () => {
  try {
    const countRes = await pool.query('SELECT COUNT(*)::int AS count FROM snmp_templates');
    const count = Number(countRes.rows[0]?.count || 0);
    if (count > 0) return;

    const defaultTemplates = [
      {
        name: 'SNMP v2c (Default)',
        version: 'v2c',
        community: 'public',
        security_name: null,
        security_level: null,
        auth_protocol: null,
        auth_key: null,
        priv_protocol: null,
        priv_key: null
      },
      {
        name: 'SNMP v3 (NoAuth)',
        version: 'v3',
        community: null,
        security_name: 'admin',
        security_level: 'noAuthNoPriv',
        auth_protocol: 'SHA',
        auth_key: null,
        priv_protocol: 'AES',
        priv_key: null
      },
      {
        name: 'SNMP v3 (Auth)',
        version: 'v3',
        community: null,
        security_name: 'admin',
        security_level: 'authNoPriv',
        auth_protocol: 'SHA',
        auth_key: 'password123',
        priv_protocol: 'AES',
        priv_key: null
      }
    ];

    for (const tpl of defaultTemplates) {
      await pool.query(
        `INSERT INTO snmp_templates (name, version, community, security_name, security_level, auth_protocol, auth_key, priv_protocol, priv_key)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [tpl.name, tpl.version, tpl.community, tpl.security_name, tpl.security_level, tpl.auth_protocol, tpl.auth_key, tpl.priv_protocol, tpl.priv_key]
      );
    }
    console.log('✓ Varsayılan SNMP Template\'leri oluşturuldu');
  } catch (err) {
    console.error('! SNMP Template seed hatası:', err.message);
  }
};

// --- SNMP Template API ---
app.get('/api/snmp-templates', async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM snmp_templates ORDER BY name ASC');
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/snmp-templates', async (req, res) => {
  try {
    const { name, version, community, security_name, security_level, auth_protocol, auth_key, priv_protocol, priv_key } = req.body;
    const r = await pool.query(
      `INSERT INTO snmp_templates (name, version, community, security_name, security_level, auth_protocol, auth_key, priv_protocol, priv_key)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
      [name, version, community, security_name, security_level, auth_protocol, auth_key, priv_protocol, priv_key]
    );
    res.status(201).json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/snmp-templates/:id', async (req, res) => {
  try {
    const { name, version, community, security_name, security_level, auth_protocol, auth_key, priv_protocol, priv_key } = req.body;
    const r = await pool.query(
      `UPDATE snmp_templates
       SET name=$1, version=$2, community=$3, security_name=$4, security_level=$5, auth_protocol=$6, auth_key=$7, priv_protocol=$8, priv_key=$9, updated_at=NOW()
       WHERE id=$10 RETURNING *`,
      [name, version, community, security_name, security_level, auth_protocol, auth_key, priv_protocol, priv_key, req.params.id]
    );
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/snmp-templates/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM snmp_templates WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- SSH Template API ---
app.get('/api/ssh-templates', async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM ssh_templates ORDER BY name ASC');
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/ssh-templates', async (req, res) => {
  try {
    const { name, username, password, port } = req.body;
    const r = await pool.query(
      `INSERT INTO ssh_templates (name, username, password, port)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [name, username, password, port || 22]
    );
    res.status(201).json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/ssh-templates/:id', async (req, res) => {
  try {
    const { name, username, password, port } = req.body;
    const r = await pool.query(
      `UPDATE ssh_templates
       SET name=$1, username=$2, password=$3, port=$4, updated_at=NOW()
       WHERE id=$5 RETURNING *`,
      [name, username, password, port || 22, req.params.id]
    );
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/ssh-templates/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM ssh_templates WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- API Template API ---
app.get('/api/api-templates', async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM api_templates ORDER BY name ASC');
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/api-templates', async (req, res) => {
  try {
    const { name, base_url, api_key, auth_type } = req.body;
    const r = await pool.query(
      `INSERT INTO api_templates (name, base_url, api_key, auth_type)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [name, base_url, api_key, auth_type || 'Bearer']
    );
    res.status(201).json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/api-templates/:id', async (req, res) => {
  try {
    const { name, base_url, api_key, auth_type } = req.body;
    const r = await pool.query(
      `UPDATE api_templates
       SET name=$1, base_url=$2, api_key=$3, auth_type=$4, updated_at=NOW()
       WHERE id=$5 RETURNING *`,
      [name, base_url, api_key, auth_type || 'Bearer', req.params.id]
    );
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/api-templates/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM api_templates WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- Connection Test API ---
app.post('/api/devices/test-connection', async (req, res) => {
  const { connection_method, ip_address, api_template_id, snmp_template_id, ssh_template_id } = req.body;
  
  try {
    if (connection_method === 'api') {
      const tplRes = await pool.query('SELECT * FROM api_templates WHERE id = $1', [api_template_id]);
      if (tplRes.rows.length === 0) throw new Error('API Template bulunamadı');
      const tpl = tplRes.rows[0];
      
      const url = `${tpl.base_url}/monitor/system/status?access_token=${tpl.api_key}`;
      const response = await axios.get(url, { 
        timeout: 5000, 
        httpsAgent: new https.Agent({ rejectUnauthorized: false }) 
      });
      
      const hostname = response.data?.results?.hostname || 'Cihaz';
      return res.json({ success: true, message: `API Bağlantısı Başarılı: ${hostname}`, hostname });
    } else {
      // SNMP + SSH Test
      const snmpTplRes = await pool.query('SELECT * FROM snmp_templates WHERE id = $1', [snmp_template_id]);
      if (snmpTplRes.rows.length === 0) throw new Error('SNMP Template bulunamadı');
      const snmpTpl = snmpTplRes.rows[0];

      const snmpInfo = await checkSnmpStatus(ip_address, snmpTpl);
      if (snmpInfo.status === 'offline') {
        throw new Error(`SNMP Hatası: ${snmpInfo.error || 'Cihaza ulaşılamadı'}`);
      }

      const sshTplRes = await pool.query('SELECT * FROM ssh_templates WHERE id = $1', [ssh_template_id]);
      if (sshTplRes.rows.length === 0) throw new Error('SSH Template bulunamadı');
      const sshTpl = sshTplRes.rows[0];

      // Quick SSH Check
      await new Promise((resolve, reject) => {
        const conn = new SSHClient();
        conn.on('ready', () => { conn.end(); resolve(); })
            .on('error', (err) => { reject(new Error(`SSH Hatası: ${err.message}`)); })
            .connect({
              host: ip_address,
              port: sshTpl.port || 22,
              username: sshTpl.username,
              password: sshTpl.password,
              readyTimeout: 5000
            });
      });

      return res.json({ 
        success: true, 
        message: 'SNMP ve SSH Bağlantısı Başarılı', 
        hostname: snmpInfo.sysName || 'Cihaz' 
      });
    }
  } catch (e) {
    res.status(400).json({ success: false, error: e.message });
  }
});

// --- Updated Device API ---
app.get('/api/devices', async (req, res) => {
  try {
    const isSnmpOnly = req.query.snmp === 'true';
    const isApiOnly = req.query.api === 'true';
    
    let query = `
      SELECT d.*, 
             st.name as snmp_template_name,
             ssht.name as ssh_template_name,
             at.name as api_template_name
      FROM devices d 
      LEFT JOIN snmp_templates st ON d.snmp_template_id = st.id
      LEFT JOIN ssh_templates ssht ON d.ssh_template_id = ssht.id
      LEFT JOIN api_templates at ON d.api_template_id = at.id
    `;
    
    let conditions = [];
    if (isSnmpOnly) {
      conditions.push(`(d.snmp_template_id IS NOT NULL OR d.manual_snmp_config IS NOT NULL)`);
    } else if (isApiOnly) {
      conditions.push(`(d.connection_method = 'api' OR d.api_key IS NOT NULL)`);
    }
    
    if (conditions.length > 0) {
      query += ` WHERE ` + conditions.join(' AND ');
    }
    
    query += ` ORDER BY d.id DESC`;
    const r = await pool.query(query);
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/devices', async (req, res) => {
  try {
    const { name, ip_address, connection_method, api_template_id, snmp_template_id, ssh_template_id, vdom } = req.body;
    
    const r = await pool.query(
      `INSERT INTO devices 
       (name, ip_address, connection_method, api_template_id, snmp_template_id, ssh_template_id, vdom) 
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [name || ip_address, ip_address, connection_method || 'snmp_ssh', api_template_id || null, snmp_template_id || null, ssh_template_id || null, vdom || 'root']
    );
    res.status(201).json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/devices/:id', async (req, res) => {
  try {
    const { name, ip_address, connection_method, api_template_id, snmp_template_id, ssh_template_id, vdom } = req.body;

    const r = await pool.query(
      `UPDATE devices
       SET name=$1, ip_address=$2, connection_method=$3, api_template_id=$4, snmp_template_id=$5, ssh_template_id=$6, vdom=$7, updated_at=NOW()
       WHERE id=$8 RETURNING *`,
      [name, ip_address, connection_method, api_template_id, snmp_template_id, ssh_template_id, vdom, req.params.id]
    );
    if (r.rows.length === 0) return res.status(404).json({ error: 'Cihaz bulunamadi.' });
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/devices/:id', async (req, res) => {
  try {
    const r = await pool.query('DELETE FROM devices WHERE id = $1 RETURNING id', [req.params.id]);
    if (r.rows.length === 0) return res.status(404).json({ error: 'Cihaz bulunamadi.' });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Live SNMP Track
app.get('/api/devices/snmp-track', async (req, res) => {
  try {
    const devs = await pool.query(`
      SELECT d.*, t.version, t.community, t.security_name, t.security_level, t.auth_protocol, t.auth_key, t.priv_protocol, t.priv_key 
      FROM devices d 
      LEFT JOIN snmp_templates t ON d.snmp_template_id = t.id
      WHERE d.snmp_template_id IS NOT NULL OR d.manual_snmp_config IS NOT NULL
    `);
    
    const results = [];
    for (const dev of devs.rows) {
      let snmpConfig = dev.manual_snmp_config || {
        version: dev.version,
        community: dev.community,
        security_name: dev.security_name,
        security_level: dev.security_level,
        auth_protocol: dev.auth_protocol,
        auth_key: dev.auth_key,
        priv_protocol: dev.priv_protocol,
        priv_key: dev.priv_key
      };

      if (!snmpConfig || !snmpConfig.version) continue;

      const info = await checkSnmpStatus(dev.ip_address, snmpConfig);
      const liveName = info.sysName ? String(info.sysName).trim() : null;
      await pool.query('UPDATE devices SET status = $1, last_sync = NOW(), metadata = $2, name = COALESCE($3, name) WHERE id = $4', 
        [info.status, JSON.stringify({ sysName: info.sysName || null }), liveName, dev.id]);
      
      results.push({ id: dev.id, name: liveName || dev.name, status: info.status, sysName: info.sysName });
    }
    
    res.json(results);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Live API Monitor
app.get('/api/devices/monitor', async (req, res) => {
  try {
    const devs = await pool.query(`SELECT * FROM devices WHERE api_key IS NOT NULL AND api_key != ''`);
    const results = [];
    
    for (const dev of devs.rows) {
      const info = await getFGT(dev.ip_address, dev.api_key);
      await pool.query('UPDATE devices SET status = $1, last_sync = NOW() WHERE id = $2', [info.status, dev.id]);
      results.push({ id: dev.id, name: dev.name, status: info.status });
    }
    
    res.json(results);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/health', (req, res) => res.json({ status: 'OK', db: isDbReady ? 'connected' : 'disconnected' }));

// --- Network Scan Helpers ---
const expandIpRange = (range) => {
  const ips = [];
  
  // Single IP
  if (!range.includes('-')) return [range];
  
  // Check if it's full IP range format: 192.168.1.100-192.168.1.105
  if (range.match(/^\d+\.\d+\.\d+\.\d+-\d+\.\d+\.\d+\.\d+$/)) {
    const [start, end] = range.split('-');
    const startParts = start.split('.').map(Number);
    const endParts = end.split('.').map(Number);
    
    // Ensure same network
    if (startParts[0] === endParts[0] && startParts[1] === endParts[1] && startParts[2] === endParts[2]) {
      const base = startParts.slice(0, 3).join('.');
      const startNum = startParts[3];
      const endNum = endParts[3];
      for (let i = startNum; i <= endNum; i++) {
        ips.push(`${base}.${i}`);
      }
      return ips;
    }
  }
  
  // Simple format: 192.168.1.1-50
  const parts = range.split('.');
  const lastPart = parts[3];
  if (!lastPart || !lastPart.includes('-')) return [range];
  
  const [start, end] = lastPart.split('-').map(Number);
  const base = parts.slice(0, 3).join('.');
  for (let i = start; i <= end; i++) {
    ips.push(`${base}.${i}`);
  }
  return ips;
};

const runBackgroundScan = async (scanId, ips, templateIds) => {
  try {
    const templatesRes = await pool.query('SELECT * FROM snmp_templates WHERE id = ANY($1)', [templateIds]);
    const templates = templatesRes.rows;

    await pool.query('UPDATE network_scans SET status = \'scanning\', progress_total = $1, progress_current = 0, updated_at = NOW() WHERE id = $2', [ips.length, scanId]);
    console.log(`Starting scan ${scanId} for ${ips.length} IPs`);

    let discoveredCount = 0;
    for (let i = 0; i < ips.length; i++) {
      // Check if scan was cancelled
      const scanCheck = await pool.query('SELECT status FROM network_scans WHERE id = $1', [scanId]);
      if (scanCheck.rows[0] && scanCheck.rows[0].status === 'cancelled') {
        console.log(`Scan ${scanId} was cancelled, stopping.`);
        return;
      }

      const ip = ips[i];
      console.log(`Checking IP ${ip} for scan ${scanId}`);
      for (const tpl of templates) {
        const info = await checkSnmpStatus(ip, tpl);
        if (info.status === 'online') {
          await pool.query(
            `INSERT INTO discovered_devices (scan_id, ip_address, hostname, snmp_template_id)
             VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
            [scanId, ip, info.sysName || 'Unknown', tpl.id]
          );
          discoveredCount++;
          console.log(`Device found: ${ip} (${info.sysName || 'Unknown'})`);
          break; // Found one working template for this IP
        }
      }
      await pool.query('UPDATE network_scans SET progress_current = $1 WHERE id = $2', [i + 1, scanId]);
    }

    await pool.query('UPDATE network_scans SET status = \'completed\', discovered_count = $1, updated_at = NOW() WHERE id = $2', [discoveredCount, scanId]);
    console.log(`Scan ${scanId} completed. Found ${discoveredCount} devices.`);
  } catch (err) {
    console.error('Scan error:', err);
    await pool.query('UPDATE network_scans SET status = \'error\', updated_at = NOW() WHERE id = $1', [scanId]);
  }
};

// --- Network Scan API ---
app.post('/api/network-scan', async (req, res) => {
  try {
    const { ip_range, snmp_template_ids } = req.body;
    const ips = expandIpRange(ip_range);
    
    const r = await pool.query(
      'INSERT INTO network_scans (ip_range, snmp_template_ids, status, progress_total) VALUES ($1, $2, \'idle\', $3) RETURNING *',
      [ip_range, snmp_template_ids, ips.length]
    );
    const scan = r.rows[0];
    
    // Start background process
    runBackgroundScan(scan.id, ips, snmp_template_ids);
    
    res.json(scan);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/network-scan/discovered', async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT dd.*, st.name as template_name, ns.ip_range as scan_range
      FROM discovered_devices dd
      JOIN snmp_templates st ON dd.snmp_template_id = st.id
      JOIN network_scans ns ON dd.scan_id = ns.id
      WHERE dd.status = 'discovered'
      ORDER BY dd.discovered_at DESC
    `);
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/network-scan/active', async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM network_scans WHERE status = \'scanning\' OR status = \'idle\' OR status = \'paused\' ORDER BY id DESC LIMIT 1');
    res.json(r.rows[0] || null);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/network-scan/history', async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT id, ip_range, status, progress_total, discovered_count, created_at, updated_at FROM network_scans WHERE status = \'completed\' OR status = \'error\' OR status = \'cancelled\' ORDER BY updated_at DESC LIMIT 10'
    );
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/network-scan/add-discovered', async (req, res) => {
  try {
    const rawId = req.body.id;
    if (!rawId) return res.status(400).json({ error: 'ID eksik' });
    
    const id = parseInt(rawId, 10);
    if (isNaN(id)) return res.status(400).json({ error: 'Geçersiz ID formatı' });

    console.log('[DEBUG] add-discovered request for ID:', id);
    
    // 1. Get discovery record
    const discoveryRes = await pool.query('SELECT * FROM discovered_devices WHERE id = $1', [id]);
    if (discoveryRes.rows.length === 0) {
      console.error('[ERROR] Discovery record not found for ID:', id);
      return res.status(404).json({ error: 'Cihaz bulunamadı' });
    }
    
    const dev = discoveryRes.rows[0];
    const devIP = String(dev.ip_address).trim();
    const devName = (dev.hostname || dev.ip_address || 'Bilinmeyen Cihaz').trim();
    const tplId = dev.snmp_template_id;

    console.log(`[DEBUG] Adding device: IP=${devIP}, Name=${devName}, TplID=${tplId}`);

    // 2. Perform UPSERT into devices table
    // Minimalist query to maximize compatibility
    try {
      await pool.query(`
        INSERT INTO devices (name, ip_address, connection_method, snmp_template_id)
        VALUES ($1, $2, 'snmp_ssh', $3)
        ON CONFLICT (ip_address) 
        DO UPDATE SET 
          name = EXCLUDED.name,
          snmp_template_id = EXCLUDED.snmp_template_id
      `, [devName, devIP, tplId]);
      console.log('[DEBUG] UPSERT successful');
    } catch (upsertErr) {
      console.error('[ERROR] UPSERT failed:', upsertErr.message);
      // Fallback if UPSERT fails (e.g. old postgres or schema mismatch)
      const existing = await pool.query('SELECT id FROM devices WHERE ip_address = $1', [devIP]);
      if (existing.rows.length > 0) {
        await pool.query('UPDATE devices SET name = $1, snmp_template_id = $2 WHERE ip_address = $3', [devName, tplId, devIP]);
      } else {
        await pool.query('INSERT INTO devices (name, ip_address, snmp_template_id) VALUES ($1, $2, $3)', [devName, devIP, tplId]);
      }
    }

    // 3. Mark as added in discovered_devices
    await pool.query("UPDATE discovered_devices SET status = 'added' WHERE id = $1", [id]);
    console.log('[DEBUG] Discovery status updated to added');
    
    res.json({ success: true });
  } catch (e) { 
    console.error('CRITICAL Error in add-discovered route:', e);
    res.status(500).json({ 
      error: 'Sunucu hatası', 
      details: e.message,
      code: e.code 
    }); 
  }
});

// Pause scan
app.post('/api/network-scan/pause', async (req, res) => {
  try {
    const { scan_id } = req.body;
    console.log('Pause request for scan:', scan_id);
    const r = await pool.query('UPDATE network_scans SET status = \'paused\', updated_at = NOW() WHERE id = $1 RETURNING *', [scan_id]);
    if (r.rows.length === 0) return res.status(404).json({ error: 'Tarama bulunamadı' });
    console.log('Scan paused successfully:', r.rows[0]);
    res.json(r.rows[0]);
  } catch (e) { 
    console.error('Pause error:', e);
    res.status(500).json({ error: e.message }); 
  }
});

// Resume scan
app.post('/api/network-scan/resume', async (req, res) => {
  try {
    const { scan_id } = req.body;
    console.log('Resume request for scan:', scan_id);
    const r = await pool.query('UPDATE network_scans SET status = \'scanning\', updated_at = NOW() WHERE id = $1 RETURNING *', [scan_id]);
    if (r.rows.length === 0) return res.status(404).json({ error: 'Tarama bulunamadı' });
    console.log('Scan resumed successfully:', r.rows[0]);
    res.json(r.rows[0]);
  } catch (e) { 
    console.error('Resume error:', e);
    res.status(500).json({ error: e.message }); 
  }
});

// Cancel scan
app.post('/api/network-scan/cancel', async (req, res) => {
  try {
    const { scan_id } = req.body;
    console.log('Cancel request for scan:', scan_id);
    const r = await pool.query('UPDATE network_scans SET status = \'cancelled\', updated_at = NOW() WHERE id = $1 RETURNING *', [scan_id]);
    if (r.rows.length === 0) return res.status(404).json({ error: 'Tarama bulunamadı' });
    console.log('Scan cancelled successfully:', r.rows[0]);
    res.json(r.rows[0]);
  } catch (e) { 
    console.error('Cancel error:', e);
    res.status(500).json({ error: e.message }); 
  }
});

// --- Topology API ---
app.get('/api/topologies', async (req, res) => {
  try {
    const r = await pool.query('SELECT id, name, created_at, updated_at FROM topologies ORDER BY updated_at DESC');
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/topologies/:id', async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM topologies WHERE id = $1', [req.params.id]);
    if (r.rows.length === 0) return res.status(404).json({ error: 'Topoloji bulunamadı' });
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/topologies', async (req, res) => {
  try {
    const { name } = req.body;
    const r = await pool.query(
      'INSERT INTO topologies (name, nodes, edges) VALUES ($1, \'[]\', \'[]\') RETURNING *',
      [name || 'Yeni Topoloji']
    );
    res.status(201).json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/topologies/:id', async (req, res) => {
  try {
    const { name, nodes, edges } = req.body;
    const r = await pool.query(
      `UPDATE topologies 
       SET name = COALESCE($1, name), 
           nodes = COALESCE($2, nodes), 
           edges = COALESCE($3, edges), 
           updated_at = NOW() 
       WHERE id = $4 RETURNING *`,
      [name, JSON.stringify(nodes), JSON.stringify(edges), req.params.id]
    );
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/topologies/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM topologies WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- Custom Icons API ---
app.get('/api/icons', async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM custom_icons ORDER BY name ASC');
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/icons', async (req, res) => {
  try {
    const { name, data } = req.body;
    if (!name || !data) return res.status(400).json({ error: 'Name and data are required' });
    const r = await pool.query(
      'INSERT INTO custom_icons (name, data) VALUES ($1, $2) RETURNING *',
      [name, data]
    );
    res.status(201).json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/icons/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM custom_icons WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Start Server
initDB().finally(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`✓ Backend started on http://localhost:${PORT}`);
  });
});
