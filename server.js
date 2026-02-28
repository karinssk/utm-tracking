const path = require('path');
const fs = require('fs');
const express = require('express');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const Database = require('better-sqlite3');
const { Client, middleware: lineMiddleware } = require('@line/bot-sdk');
require('dotenv').config();

const PORT = process.env.PORT || 3000;
const LIFF_ID = process.env.LIFF_ID || '';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);

const lineConfig = {
  channelAccessToken: process.env.LINE_CHANNEL_ACCESS_TOKEN || '',
  channelSecret: process.env.LINE_CHANNEL_SECRET || '',
};

if (!lineConfig.channelAccessToken || !lineConfig.channelSecret) {
  console.warn('[WARN] LINE credentials are not fully set. Webhook replies will fail until they are provided.');
}
if (!LIFF_ID) {
  console.warn('[WARN] LIFF_ID is missing; liffUrl responses will be blank until set.');
}

// --- Express setup ---
const app = express();
app.set('trust proxy', true);
app.use(express.json());
app.use(cors({
  origin(origin, callback) {
    if (!origin || ALLOWED_ORIGINS.length === 0 || ALLOWED_ORIGINS.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('Not allowed by CORS'));
  },
}));

// Simple rate limiter for /api/visit (per IP)
const VISIT_LIMIT = 60; // requests
const VISIT_WINDOW_MS = 60 * 1000; // 1 minute
const visitBucket = new Map();

function rateLimit(req, res, next) {
  const ip = req.ip || 'unknown';
  const now = Date.now();
  const bucket = visitBucket.get(ip) || { count: 0, start: now };
  if (now - bucket.start > VISIT_WINDOW_MS) {
    bucket.count = 0;
    bucket.start = now;
  }
  bucket.count += 1;
  visitBucket.set(ip, bucket);
  if (bucket.count > VISIT_LIMIT) {
    return res.status(429).json({ message: 'Too many requests' });
  }
  return next();
}

// --- SQLite setup ---
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}
const dbPath = path.join(dataDir, 'tracking.db');
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.prepare(`
CREATE TABLE IF NOT EXISTS leads (
  id TEXT PRIMARY KEY,
  tracking_id TEXT UNIQUE,
  utm_source TEXT,
  utm_medium TEXT,
  utm_campaign TEXT,
  utm_term TEXT,
  utm_content TEXT,
  source_url TEXT,
  user_agent TEXT,
  ip TEXT,
  line_user_id TEXT,
  line_display_name TEXT,
  line_picture TEXT,
  line_status_message TEXT,
  linked_at TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);
`).run();

db.prepare('CREATE INDEX IF NOT EXISTS idx_leads_tracking_id ON leads (tracking_id);').run();
db.prepare('CREATE INDEX IF NOT EXISTS idx_leads_line_user_id ON leads (line_user_id);').run();

const insertLead = db.prepare(`
  INSERT INTO leads (
    id, tracking_id, utm_source, utm_medium, utm_campaign, utm_term, utm_content,
    source_url, user_agent, ip, line_user_id, line_display_name, line_picture, line_status_message, linked_at
  ) VALUES (
    @id, @tracking_id, @utm_source, @utm_medium, @utm_campaign, @utm_term, @utm_content,
    @source_url, @user_agent, @ip, @line_user_id, @line_display_name, @line_picture, @line_status_message, @linked_at
  )
`);

const updateLeadWithLine = db.prepare(`
  UPDATE leads SET
    line_user_id = @line_user_id,
    line_display_name = @line_display_name,
    line_picture = @line_picture,
    line_status_message = @line_status_message,
    linked_at = datetime('now')
  WHERE tracking_id = @tracking_id
`);

const selectLeadByTracking = db.prepare('SELECT * FROM leads WHERE tracking_id = ?');

// --- Helpers ---
function sanitize(input, max = 255) {
  if (!input || typeof input !== 'string') return null;
  return input.slice(0, max).trim();
}

function buildLiffUrl(trackingId) {
  if (!LIFF_ID) return '';
  return `https://liff.line.me/${LIFF_ID}?tid=${encodeURIComponent(trackingId)}`;
}

// --- Routes ---
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.get('/api/config', (req, res) => {
  res.json({ liffId: LIFF_ID });
});

// Serve landing page at root
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'landing.html'));
});

app.post('/api/visit', rateLimit, (req, res) => {
  const body = req.body || {};
  const trackingId = uuidv4();
  const ip = req.ip || '';
  const userAgent = req.get('user-agent') || '';

  const lead = {
    id: uuidv4(),
    tracking_id: trackingId,
    utm_source: sanitize(body.utm_source),
    utm_medium: sanitize(body.utm_medium),
    utm_campaign: sanitize(body.utm_campaign),
    utm_term: sanitize(body.utm_term),
    utm_content: sanitize(body.utm_content),
    source_url: sanitize(body.source_url || req.get('referer') || req.get('origin') || '' , 500),
    user_agent: sanitize(userAgent, 500),
    ip: sanitize(ip, 100),
    line_user_id: null,
    line_display_name: null,
    line_picture: null,
    line_status_message: null,
    linked_at: null,
  };

  try {
    insertLead.run(lead);
  } catch (err) {
    console.error('Failed to insert lead', err);
    return res.status(500).json({ message: 'Failed to save tracking data' });
  }

  const liffUrl = buildLiffUrl(trackingId);
  return res.json({ trackingId, liffUrl });
});

app.post('/api/link', (req, res) => {
  const {
    trackingId,
    lineUserId,
    displayName,
    pictureUrl,
    statusMessage,
  } = req.body || {};

  if (!trackingId) {
    return res.status(400).json({ message: 'trackingId is required' });
  }

  const payload = {
    tracking_id: trackingId,
    line_user_id: sanitize(lineUserId, 128),
    line_display_name: sanitize(displayName, 255),
    line_picture: sanitize(pictureUrl, 500),
    line_status_message: sanitize(statusMessage, 500),
  };

  try {
    const existing = selectLeadByTracking.get(trackingId);
    if (existing) {
      updateLeadWithLine.run(payload);
    } else {
      insertLead.run({
        id: uuidv4(),
        tracking_id: trackingId,
        utm_source: null,
        utm_medium: null,
        utm_campaign: null,
        utm_term: null,
        utm_content: null,
        source_url: null,
        user_agent: null,
        ip: null,
        line_user_id: payload.line_user_id,
        line_display_name: payload.line_display_name,
        line_picture: payload.line_picture,
        line_status_message: payload.line_status_message,
        linked_at: new Date().toISOString(),
      });
    }
  } catch (err) {
    console.error('Failed to link LINE user', err);
    return res.status(500).json({ message: 'Failed to link LINE user' });
  }

  return res.json({ message: 'linked' });
});

if (lineConfig.channelAccessToken && lineConfig.channelSecret) {
  const lineClient = new Client(lineConfig);

  app.post('/line/webhook', lineMiddleware(lineConfig), async (req, res) => {
    const events = req.body.events || [];

    const results = await Promise.all(events.map(async (event) => {
      if (event.type === 'follow' && event.replyToken) {
        const tid = `direct-${Date.now()}`;
        const liffLink = buildLiffUrl(tid);
        const message = {
          type: 'text',
          text: liffLink
            ? `ขอบคุณที่แอด LINE OA ของเรา\nกดลิงก์นี้เพื่อลงทะเบียน: ${liffLink}`
            : 'ขอบคุณที่แอด LINE OA ของเรา',
        };
        try {
          await lineClient.replyMessage(event.replyToken, message);
        } catch (err) {
          console.error('LINE reply error', err.originalError || err);
        }
      }
    }));

    return res.json(results);
  });
} else {
  app.post('/line/webhook', (req, res) => res.status(503).json({ message: 'LINE credentials missing' }));
}

app.use(express.static(path.join(__dirname, 'public')));

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
