require('dotenv').config({ path: '../.env' });
const { Pool } = require('pg');

const pool = new Pool({
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5433,
  database: process.env.DB_NAME
});

async function clearDatabase() {
  try {
    console.log(`Veritabanına bağlanılıyor (${pool.options.host}:${pool.options.port})...`);
    const client = await pool.connect();
    console.log('Bağlantı başarılı. Kayıtlar siliniyor...');
    
    await client.query('DELETE FROM parsed_config_items');
    await client.query('DELETE FROM uploaded_files');
    
    console.log('✓ Tüm kayıtlar başarıyla silindi.');
    client.release();
    process.exit(0);
  } catch (err) {
    console.error('Hata Detayı:', err);
    process.exit(1);
  }
}

clearDatabase();
