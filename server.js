'use strict';

require('dotenv').config();
const fastify = require('fastify')({ logger: true });
const { Client } = require('pg');

// 1. Ensure DATABASE_URL exists before starting
if (!process.env.DATABASE_URL) {
  console.error("CRITICAL ERROR: DATABASE_URL is not defined in Environment Variables.");
  process.exit(1);
}

// 2. SSL is REQUIRED for Render's free PostgreSQL databases
const client = new Client({ 
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } 
});

const EXPECTED_SALT = (process.env.SECRET_SALT || '').trim();

fastify.post('/verify', async (request, reply) => {
  const body = request.body || {};
  const key = typeof body.key === 'string' ? body.key.trim() : '';
  const hwid = typeof body.hwid === 'string' ? body.hwid.trim() : '';
  const secretSalt = typeof body.secret_salt === 'string' ? body.secret_salt.trim() : '';

  if (!EXPECTED_SALT || secretSalt !== EXPECTED_SALT) {
    return reply.send({ status: 'invalid' });
  }
  if (!key || !hwid) {
    return reply.send({ status: 'invalid' });
  }

  try {
    const res = await client.query(
      'SELECT license_key, expiry_date, status, hwid, customer_name FROM licenses WHERE license_key = $1',
      [key],
    );
    const license = res.rows[0];

    if (!license) return reply.send({ status: 'invalid' });
    if (license.status !== 'active') return reply.send({ status: 'revoked' });

    const expiry = new Date(license.expiry_date);
    if (Number.isNaN(expiry.getTime()) || new Date() > expiry) {
      return reply.send({ status: 'expired' });
    }

    // First activation: bind HWID
    if (!license.hwid) {
      await client.query('UPDATE licenses SET hwid = $1 WHERE license_key = $2', [
        hwid,
        key,
      ]);
      return reply.send({
        status: 'active',
        type: 'standard',
        licensedTo: license.customer_name || 'Licensed User',
        name: license.customer_name || 'Licensed User',
      });
    }

    if (license.hwid !== hwid) {
      return reply.send({ status: 'hwid_mismatch' });
    }

    return reply.send({
      status: 'active',
      type: 'standard',
      licensedTo: license.customer_name || 'Licensed User',
      name: license.customer_name || 'Licensed User',
    });
  } catch (err) {
    fastify.log.error(err);
    return reply.code(500).send({ status: 'invalid' });
  }
});

fastify.get('/generate', async (request, reply) => {
  const adminPass = request.query.admin_pass;
  const keyName =
    typeof request.query.key_name === 'string'
      ? request.query.key_name.trim().slice(0, 200)
      : '';

  if (adminPass !== process.env.ADMIN_PASSWORD) {
    return reply.code(401).send({ error: 'Unauthorized' });
  }

  const newKey = `GEM-${Math.random().toString(36).substring(2, 10).toUpperCase()}`;

  try {
    await client.query(
      `INSERT INTO licenses (license_key, expiry_date, status, customer_name)
       VALUES ($1, CURRENT_DATE + INTERVAL '30 days', 'active', $2)`,
      [newKey, keyName || null],
    );
    return reply.send({
      success: true,
      key: newKey,
      message: 'Valid for 30 days',
    });
  } catch (err) {
    fastify.log.error(err);
    return reply.code(500).send({ error: 'Database error' });
  }
});

async function main() {
  try {
    // 3. Connect to the database
    await client.connect();
    fastify.log.info("Connected to database successfully");

    // 4. Render requires binding to 0.0.0.0 and using process.env.PORT
    const port = process.env.PORT || 10000;
    await fastify.listen({ port: Number(port), host: '0.0.0.0' });
    
    fastify.log.info(`Gemhunter auth listening on port ${port}`);
  } catch (err) {
    console.error("Setup Error:", err);
    process.exit(1);
  }
}

main();
