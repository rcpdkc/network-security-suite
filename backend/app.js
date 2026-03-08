require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');
const FortiGateParser = require('./fortigate-parser');

const app = express();
const PORT = process.env.PORT || 5000;

// Load Security KB
const kbPath = path.join(__dirname, 'data', 'security_kb.json');
const kbMetadataPath = path.join(__dirname, 'data', 'security_kb_metadata.json');
let securityKB = [];
try {
  if (fs.existsSync(kbPath)) {
    const rawKB = JSON.parse(fs.readFileSync(kbPath, 'utf8'));
    let metadataById = {};
    if (fs.existsSync(kbMetadataPath)) {
      const metadata = JSON.parse(fs.readFileSync(kbMetadataPath, 'utf8'));
      metadataById = Object.fromEntries(metadata.map((item) => [item.id, item]));
    }
    securityKB = rawKB.map((rule) => ({ ...rule, ...(metadataById[rule.id] || {}) }));
    console.log(`✓ Güvenlik Bilgi Tabanı yüklendi (${securityKB.length} kural)`);
  }
} catch (err) {
  console.error('✗ KB yükleme hatası:', err.message);
}

// Middleware
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type']
}));
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));

// Multer
const storage = multer.memoryStorage();
const upload = multer({
  storage: storage,
  limits: { fileSize: 50 * 1024 * 1024 }
});

// DB Connection
const pool = new Pool({
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME
});

let isDbReady = false;
const checkDatabase = async () => {
  try {
    await pool.query('SELECT NOW()');
    console.log('✓ Veritabanına başarıyla bağlanıldı');
    isDbReady = true;

    // Create devices table if not exists
    await pool.query(`
      CREATE TABLE IF NOT EXISTS devices (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        ip_address VARCHAR(255) NOT NULL,
        api_key TEXT NOT NULL,
        vdom VARCHAR(100) DEFAULT 'root',
        status VARCHAR(50) DEFAULT 'unknown',
        last_sync TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('✓ Cihazlar tablosu hazır');
  } catch (err) {
    console.error('✗ Veritabanı bağlantı veya tablo oluşturma hatası:', err.message);
  }
};

// ... existing buildAnalysisPayload ...

// --- Device API Endpoints ---

// List Devices
app.get('/api/devices', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name, ip_address, vdom, status, last_sync, created_at FROM devices ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Add Device
app.post('/api/devices', async (req, res) => {
  try {
    const { name, ip_address, api_key, vdom } = req.body;
    if (!name || !ip_address || !api_key) return res.status(400).json({ error: 'Eksik bilgiler' });
    
    const result = await pool.query(
      'INSERT INTO devices (name, ip_address, api_key, vdom) VALUES ($1, $2, $3, $4) RETURNING id',
      [name, ip_address, api_key, vdom || 'root']
    );
    res.status(201).json({ success: true, id: result.rows[0].id });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete Device
app.delete('/api/devices/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM devices WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update Device
app.put('/api/devices/:id', async (req, res) => {
  try {
    const { name, ip_address, api_key, vdom } = req.body;
    await pool.query(
      'UPDATE devices SET name = $1, ip_address = $2, api_key = $3, vdom = $4, updated_at = CURRENT_TIMESTAMP WHERE id = $5',
      [name, ip_address, api_key, vdom, req.params.id]
    );
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Sync Device (Placeholder for now - would fetch config via FortiGate API)
app.post('/api/devices/:id/sync', async (req, res) => {
  try {
    const deviceResult = await pool.query('SELECT * FROM devices WHERE id = $1', [req.params.id]);
    if (deviceResult.rows.length === 0) return res.status(404).json({ error: 'Cihaz bulunamadı' });
    
    const device = deviceResult.rows[0];
    // In a real implementation, we would use axios to call FortiGate API:
    // https://<ip>/api/v2/monitor/system/config/backup?access_token=<api_key>
    
    res.status(501).json({ error: 'API üzerinden konfigürasyon çekme henüz aktif değil. Lütfen manuel dosya yükleyin.' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const buildAnalysisPayload = (fileContent) => {
  const parser = new FortiGateParser(fileContent);
  parser.parse();

  const summaryData = parser.getSummary();
  const policyAnalysis = parser.analyzePolicies(securityKB);

  return {
    summaryData,
    finalAnalysisData: {
      ...policyAnalysis,
      summary: summaryData
    }
  };
};

// Health
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'Backend is running', database: isDbReady ? 'connected' : 'error' });
});

app.get('/api/db-status', async (req, res) => {
  if (!isDbReady) return res.status(503).json({ status: 'ERROR' });
  res.json({ status: 'OK' });
});

// Upload
app.post('/api/upload-config', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'Dosya yok' });
    const fileUid = uuidv4();
    const fileContent = req.file.buffer.toString('utf-8');
    await pool.query(
      'INSERT INTO uploaded_files (file_uid, file_name, file_content, file_size, upload_status) VALUES ($1, $2, $3, $4, $5)',
      [fileUid, req.file.originalname, fileContent, req.file.size, 'uploaded']
    );
    res.status(201).json({ success: true, fileUid });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Parse & Analyze
app.post('/api/parse-config', async (req, res) => {
  try {
    const { fileUid } = req.body;
    const fileResult = await pool.query('SELECT * FROM uploaded_files WHERE file_uid = $1', [fileUid]);
    if (fileResult.rows.length === 0) return res.status(404).json({ error: 'Dosya yok' });

    const file = fileResult.rows[0];
    const parser = new FortiGateParser(file.file_content);
    const parsedItems = parser.parse();
    const { summaryData, finalAnalysisData } = buildAnalysisPayload(file.file_content);

    let insertedCount = 0;
    await pool.query('DELETE FROM parsed_config_items WHERE file_uid = $1', [fileUid]);
    for (const item of parsedItems) {
      await pool.query(
        `INSERT INTO parsed_config_items (file_uid, item_type, item_name, config_key, config_value, raw_data, parse_order)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [fileUid, item.item_type, item.item_name, item.config_key, item.config_value, item.raw_data, item.parse_order]
      );
      insertedCount++;
    }

    await pool.query(
      'UPDATE uploaded_files SET parse_status = $1, summary_data = $2, analysis_data = $3, updated_at = CURRENT_TIMESTAMP WHERE file_uid = $4',
      ['parsed', JSON.stringify(summaryData), JSON.stringify(finalAnalysisData), fileUid]
    );

    res.json({ success: true, itemsCount: insertedCount, analysis: finalAnalysisData });
  } catch (error) {
    console.error('Parse error:', error);
    res.status(500).json({ error: error.message });
  }
});

// List Files
app.get('/api/uploaded-files', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, file_uid, file_name, file_size, parse_status, created_at FROM uploaded_files ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// File Detail
app.get('/api/config-detail/:fileUid', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM uploaded_files WHERE file_uid = $1', [req.params.fileUid]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Dosya yok' });
    
    const file = result.rows[0];
    if (file.file_content) {
      const { summaryData, finalAnalysisData } = buildAnalysisPayload(file.file_content);
      file.summary_data = summaryData;
      file.analysis_data = finalAnalysisData;

      await pool.query(
        'UPDATE uploaded_files SET summary_data = $1, analysis_data = $2, updated_at = CURRENT_TIMESTAMP WHERE file_uid = $3',
        [JSON.stringify(summaryData), JSON.stringify(finalAnalysisData), req.params.fileUid]
      );
    } else {
      if (file.analysis_data) {
        try {
          file.analysis_data = typeof file.analysis_data === 'string' ? JSON.parse(file.analysis_data) : file.analysis_data;
        } catch (e) {}
      }
      if (file.summary_data) {
        try {
          file.summary_data = typeof file.summary_data === 'string' ? JSON.parse(file.summary_data) : file.summary_data;
        } catch (e) {}
      }
    }
    
    res.json({ file });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Start
checkDatabase().then(() => {
  app.listen(PORT, () => console.log(`✓ Backend running on port ${PORT}`));
});
