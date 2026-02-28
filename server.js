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
const ALLOW_ALL_ORIGINS = ALLOWED_ORIGINS.length === 0 || ALLOWED_ORIGINS.includes('*');
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || '';

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
if (!ADMIN_PASS) {
  console.warn('[WARN] ADMIN_PASS is empty; admin panel will be unprotected until set.');
}

// --- Express setup ---
const app = express();
app.set('trust proxy', true);

// Use JSON body parser for all routes EXCEPT /line/webhook (LINE SDK handles raw body itself)
const jsonParser = express.json();
app.use((req, res, next) => {
  if (req.path === '/line/webhook') return next();
  return jsonParser(req, res, next);
});

// Log every request with status and latency
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`[REQ] ${req.method} ${req.originalUrl} ${res.statusCode} ${duration}ms ip=${req.ip || ''}`);
  });
  next();
});
app.use(cors({
  origin(origin, callback) {
    if (ALLOW_ALL_ORIGINS || !origin || ALLOWED_ORIGINS.includes(origin)) {
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
const selectAllLeads = db.prepare('SELECT * FROM leads ORDER BY created_at DESC');
const selectLeadByLineUserId = db.prepare('SELECT * FROM leads WHERE line_user_id = ? ORDER BY created_at DESC');
const updateLeadWithLineById = db.prepare(`
  UPDATE leads SET
    tracking_id = COALESCE(tracking_id, @tracking_id),
    line_user_id = @line_user_id,
    line_display_name = @line_display_name,
    line_picture = @line_picture,
    line_status_message = @line_status_message,
    linked_at = datetime('now')
  WHERE id = @id
`);

// --- Helpers ---
function sanitize(input, max = 255) {
  if (!input || typeof input !== 'string') return null;
  return input.slice(0, max).trim();
}

function buildLiffUrl(trackingId) {
  if (!LIFF_ID) return '';
  return `https://liff.line.me/${LIFF_ID}?tid=${encodeURIComponent(trackingId)}`;
}

function requireAdmin(req, res, next) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Basic ')) {
    return res.status(401).set('WWW-Authenticate', 'Basic realm=\"admin\"').send('Auth required');
  }
  const decoded = Buffer.from(header.split(' ')[1], 'base64').toString();
  const [user, pass] = decoded.split(':');
  if (user === ADMIN_USER && pass === ADMIN_PASS) return next();
  return res.status(401).set('WWW-Authenticate', 'Basic realm=\"admin\"').send('Invalid credentials');
}

// --- Routes ---
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.get('/api/config', (req, res) => {
  res.json({ liffId: LIFF_ID });
});

// --- Admin panel ---
app.get('/admin', requireAdmin, (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.send(`<!doctype html>
<html lang="th">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Admin | Leads</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 0; background: #0f172a; color: #e2e8f0; }
    header { padding: 16px 20px; background: #111827; border-bottom: 1px solid #1f2937; }
    h1 { margin: 0; font-size: 18px; }
    main { padding: 20px; overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { padding: 8px 10px; border-bottom: 1px solid #1f2937; }
    th { text-align: left; background: #111827; position: sticky; top: 0; z-index: 1; }
    tr:nth-child(even) { background: #0b1220; }
    code { font-size: 12px; color: #cbd5e1; }
  </style>
</head>
<body>
  <header><h1>Leads dashboard</h1></header>
  <main>
    <div id="meta">Loading...</div>
    <table id="grid" hidden>
      <thead>
        <tr>
          <th>Created</th><th>Tracking</th><th>UTM Source</th><th>UTM Medium</th><th>UTM Campaign</th><th>UTM Term</th><th>UTM Content</th><th>LINE User</th><th>Name</th><th>Linked</th><th>Source URL</th><th>IP</th><th>User Agent</th>
        </tr>
      </thead>
      <tbody></tbody>
    </table>
  </main>
  <script>
    async function loadData() {
      const res = await fetch('/admin/data');
      if (!res.ok) throw new Error('โหลดข้อมูลไม่ได้');
      return res.json();
    }
    function fmt(d) { return d ? new Date(d).toLocaleString('th-TH') : ''; }
    function render(rows) {
      const tbody = document.querySelector('#grid tbody');
      tbody.innerHTML = '';
      rows.forEach(r => {
        const tr = document.createElement('tr');
        tr.innerHTML = [
          '<td>', fmt(r.created_at), '</td>',
          '<td><code>', (r.tracking_id || ''), '</code></td>',
          '<td>', (r.utm_source || ''), '</td>',
          '<td>', (r.utm_medium || ''), '</td>',
          '<td>', (r.utm_campaign || ''), '</td>',
          '<td>', (r.utm_term || ''), '</td>',
          '<td>', (r.utm_content || ''), '</td>',
          '<td><code>', (r.line_user_id || ''), '</code></td>',
          '<td>', (r.line_display_name || ''), '</td>',
          '<td>', fmt(r.linked_at), '</td>',
          '<td>', (r.source_url || ''), '</td>',
          '<td>', (r.ip || ''), '</td>',
          '<td>', (r.user_agent || ''), '</td>'
        ].join('');
        tbody.appendChild(tr);
      });
      document.getElementById('grid').hidden = false;
      document.getElementById('meta').textContent = 'ทั้งหมด ' + rows.length + ' รายการ';
    }
    loadData().then(render).catch(err => {
      document.getElementById('meta').textContent = err.message || 'error';
    });
  </script>
</body>
</html>`);
});

app.get('/admin/data', requireAdmin, (req, res) => {
  res.set('Cache-Control', 'no-store');
  try {
    const rows = selectAllLeads.all();
    return res.json(rows);
  } catch (err) {
    console.error('Admin fetch error', err);
    return res.status(500).json({ message: 'Failed to load data' });
  }
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
    console.log(`[VISIT] saved tracking_id=${trackingId}`);
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
      console.log(`[LINK] updated tracking_id=${trackingId} line_user_id=${payload.line_user_id || ''}`);
    } else if (payload.line_user_id) {
      const byUser = selectLeadByLineUserId.get(payload.line_user_id);
      if (byUser) {
        updateLeadWithLineById.run({
          id: byUser.id,
          tracking_id: trackingId,
          ...payload,
        });
        console.log(`[LINK] updated existing user line_user_id=${payload.line_user_id} with tracking_id=${trackingId}`);
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
        console.log(`[LINK] inserted new tracking_id=${trackingId} line_user_id=${payload.line_user_id || ''}`);
      }
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
      console.log(`[LINK] inserted new tracking_id=${trackingId} (no line_user_id provided)`);
    }
  } catch (err) {
    console.error('Failed to link LINE user', err);
    return res.status(500).json({ message: 'Failed to link LINE user' });
  }

  return res.json({ message: 'linked' });
});

if (lineConfig.channelAccessToken && lineConfig.channelSecret) {
  const lineClient = new Client(lineConfig);

  // LINE webhook expects raw body for signature verification; middleware must be the first handler for this route
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
