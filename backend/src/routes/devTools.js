import { Router } from 'express';
import { pool } from '../db.js';
import { requireAuth } from './auth.js';

const router = Router();

// DELETE /api/dev/orders — truncate all orders and message_logs
router.delete('/orders', requireAuth, async (_req, res) => {
  try {
    await pool.query('DELETE FROM message_logs');
    await pool.query('DELETE FROM orders');
    res.json({ ok: true, message: 'All orders and message logs deleted' });
  } catch (err) {
    console.error('[dev/orders delete]', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// DELETE /api/dev/orders/reset-seq — clear orders and reset running number
router.delete('/orders/reset-seq', requireAuth, async (_req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM message_logs WHERE order_id IS NOT NULL');
    await client.query('DELETE FROM orders');
    await client.query("ALTER SEQUENCE IF EXISTS order_seq RESTART WITH 1");
    await client.query('COMMIT');
    res.json({ ok: true, message: 'Orders cleared and running number reset (next order is ...-001)' });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[dev/orders reset-seq]', err);
    res.status(500).json({ error: 'Internal server error' });
  } finally {
    client.release();
  }
});

// DELETE /api/dev/messages — truncate message_logs only
router.delete('/messages', requireAuth, async (_req, res) => {
  try {
    await pool.query('DELETE FROM message_logs');
    res.json({ ok: true, message: 'All message logs deleted' });
  } catch (err) {
    console.error('[dev/messages delete]', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// DELETE /api/dev/customers — delete all customers (LINE users) and their related data
router.delete('/customers', requireAuth, async (_req, res) => {
  try {
    await pool.query('DELETE FROM message_logs');
    await pool.query('DELETE FROM orders');
    await pool.query('UPDATE utm_sessions SET line_uid = NULL, linked_at = NULL');
    await pool.query('DELETE FROM customers');
    res.json({ ok: true, message: 'All customers and their related data deleted' });
  } catch (err) {
    console.error('[dev/customers delete]', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
