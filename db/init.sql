-- Network Security Suite Veritabanı İnitiyalizasyonu

-- pgcrypto eklentisini ekle (gen_random_uuid() için)
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- network_policies tablosu
CREATE TABLE IF NOT EXISTS network_policies (
  id SERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  rules JSONB,
  active BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- security_rules tablosu
CREATE TABLE IF NOT EXISTS security_rules (
  id SERIAL PRIMARY KEY,
  policy_id INTEGER NOT NULL REFERENCES network_policies(id) ON DELETE CASCADE,
  rule_type VARCHAR(50) NOT NULL,
  source_ip INET,
  destination_ip INET,
  port_range VARCHAR(20),
  protocol VARCHAR(10),
  action VARCHAR(20) NOT NULL,
  enabled BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- audit_logs tablosu
CREATE TABLE IF NOT EXISTS audit_logs (
  id SERIAL PRIMARY KEY,
  action VARCHAR(255) NOT NULL,
  details JSONB,
  user_ip INET,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- firewall_events tablosu
CREATE TABLE IF NOT EXISTS firewall_events (
  id SERIAL PRIMARY KEY,
  event_type VARCHAR(50) NOT NULL,
  source_ip INET,
  destination_ip INET,
  port INTEGER,
  protocol VARCHAR(10),
  action VARCHAR(20),
  blocked BOOLEAN,
  details JSONB,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- uploaded_files tablosu (FortiGate config dosyaları)
CREATE TABLE IF NOT EXISTS uploaded_files (
  id SERIAL PRIMARY KEY,
  file_uid UUID DEFAULT gen_random_uuid() UNIQUE,
  file_name VARCHAR(255) NOT NULL,
  file_content TEXT NOT NULL,
  device_model VARCHAR(100),
  device_serial VARCHAR(100),
  upload_status VARCHAR(50) DEFAULT 'uploaded',
  parse_status VARCHAR(50) DEFAULT 'pending',
  file_size INTEGER,
  summary_data JSONB,
  analysis_data JSONB,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- parsed_config_items tablosu (Parse edilen özellikler)
CREATE TABLE IF NOT EXISTS parsed_config_items (
  id SERIAL PRIMARY KEY,
  file_uid UUID NOT NULL REFERENCES uploaded_files(file_uid) ON DELETE CASCADE,
  item_type VARCHAR(100) NOT NULL,
  item_name VARCHAR(255),
  config_key VARCHAR(255),
  config_value TEXT,
  raw_data JSONB,
  parse_order INTEGER,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Index'ler
CREATE INDEX idx_policies_active ON network_policies(active);
CREATE INDEX idx_rules_policy ON security_rules(policy_id);
CREATE INDEX idx_audit_logs_created ON audit_logs(created_at);
CREATE INDEX idx_firewall_events_created ON firewall_events(created_at);
CREATE INDEX idx_uploaded_files_uid ON uploaded_files(file_uid);
CREATE INDEX idx_uploaded_files_status ON uploaded_files(parse_status);
CREATE INDEX idx_parsed_items_uid ON parsed_config_items(file_uid);
CREATE INDEX idx_parsed_items_type ON parsed_config_items(item_type);

-- View'ler
CREATE OR REPLACE VIEW policy_summary AS
SELECT 
  p.id,
  p.name,
  p.active,
  COUNT(sr.id) as rule_count,
  p.created_at
FROM network_policies p
LEFT JOIN security_rules sr ON p.id = sr.policy_id
GROUP BY p.id, p.name, p.active, p.created_at;

-- Fonksiyonlar
CREATE OR REPLACE FUNCTION update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = CURRENT_TIMESTAMP;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger
CREATE TRIGGER update_policies_timestamp
BEFORE UPDATE ON network_policies
FOR EACH ROW
EXECUTE FUNCTION update_timestamp();
