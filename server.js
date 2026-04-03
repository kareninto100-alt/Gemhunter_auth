'use strict';

require('dotenv').config();
const fastify = require('fastify')({ logger: true });
const { Client } = require('pg');

if (!process.env.DATABASE_URL) {
  console.error("CRITICAL ERROR: DATABASE_URL is not defined.");
  process.exit(1);
}

const client = new Client({ 
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } 
});

const EXPECTED_SALT = (process.env.SECRET_SALT || '').trim();

// --- ROUTES ---

fastify.post('/verify', async (request, reply) => {
  const body = request.body || {};
  const { key, hwid, secret_salt } = body;

  if (!EXPECTED_SALT || secret_salt !== EXPECTED_SALT) return reply.send({ status: 'invalid' });
  
  try {
    const res = await client.query(
      'SELECT license_key, expiry_date, status, hwid, customer_name FROM licenses WHERE license_key = $1',
      [key]
    );
    const license = res.rows[0];

    if (!license) return reply.send({ status: 'invalid' });
    if (license.status !== 'active') return reply.send({ status: 'revoked' });

    if (!license.hwid) {
      await client.query('UPDATE licenses SET hwid = $1 WHERE license_key = $2', [hwid, key]);
      return reply.send({ status: 'active', licensedTo: license.customer_name || 'User' });
    }

    if (license.hwid !== hwid) return reply.send({ status: 'hwid_mismatch' });
    return reply.send({ status: 'active', licensedTo: license.customer_name || 'User' });
  } catch (err) {
    return reply.code(500).send({ status: 'invalid' });
  }
});

fastify.get('/generate', async (request, reply) => {
  if (request.query.admin_pass !== process.env.ADMIN_PASSWORD) {
    return reply.code(401).send({ error: 'Unauthorized' });
  }
  const newKey = `GEM-${Math.random().toString(36).substring(2, 10).toUpperCase()}`;
  try {
    await client.query(
      `INSERT INTO licenses (license_key, expiry_date, status, customer_name)
       VALUES ($1, CURRENT_DATE + INTERVAL '30 days', 'active', $2)`,
      [newKey, request.query.key_name || null]
    );
    return reply.send({ success: true, key: newKey });
  } catch (err) {
    fastify.log.error(err);
    return reply.code(500).send({ error: 'Database error' });
  }
});

// --- AUTO-SETUP & STARTUP ---

async function main() {
  try {
    const port = process.env.PORT || 10000;
    await fastify.listen({ port: Number(port), host: '0.0.0.0' });
    console.log(`✅ Server bound to port ${port}`);

    await client.connect();
    console.log("✅ Connected to PostgreSQL.");

    // THIS REPLACES THE $7 SHELL ACCESS:
    console.log("🛠️ Running Auto-Table Setup...");
    await client.query(`
      CREATE TABLE IF NOT EXISTS licenses (
        license_key TEXT PRIMARY KEY,
        hwid TEXT,
        expiry_date TIMESTAMP,
        status TEXT DEFAULT 'active',
        customer_name TEXT
      );
    `);
    console.log("🎉 Database table is ready!");

  } catch (err) {
    console.error("❌ Startup Error:", err);
    process.exit(1);
  }
}

main();
