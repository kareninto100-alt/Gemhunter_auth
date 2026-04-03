'use strict';

/**
 * Gemhunter Sender license server — must match client in ../src/license.ts:
 * - POST JSON: { key, hwid, secret_salt, heartbeat?: boolean }
 * - Success: { status: "active", licensedTo?, name?, type? }
 * - HWID conflict: status one of hwid_mismatch | wrong_machine | machine_mismatch | binding_mismatch
 * - Revoked / expired: status "revoked" | "expired"
 * - Invalid key or salt: status "invalid" (client treats non-active as invalid)
 */

require('dotenv').config();
const fastify = require('fastify')({ logger: true });
const { Client } = require('pg');

const client = new Client({ connectionString: process.env.DATABASE_URL });

const EXPECTED_SALT = (process.env.SECRET_SALT || '').trim();

fastify.post('/verify', async (request, reply) => {
  const body = request.body || {};
  const key = typeof body.key === 'string' ? body.key.trim() : '';
  const hwid = typeof body.hwid === 'string' ? body.hwid.trim() : '';
  const secretSalt =
    typeof body.secret_salt === 'string' ? body.secret_salt.trim() : '';

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

    if (!license) {
      return reply.send({ status: 'invalid' });
    }

    if (license.status !== 'active') {
      return reply.send({ status: 'revoked' });
    }

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
      // Sender only treats these status strings as HWID mismatch (see license.ts)
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

/**
 * Admin: create a 30-day key. Protect ADMIN_PASSWORD in production.
 * GET /generate?admin_pass=...&key_name=Acme%20Corp
 */
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
  await client.connect();
  const port = Number(process.env.PORT) || 3000;
  const host = process.env.HOST || '0.0.0.0';
  await fastify.listen({ port, host });
  fastify.log.info(`Gemhunter auth listening on http://${host}:${port}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
