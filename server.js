require('dotenv').config();

const express      = require('express');
const helmet       = require('helmet');
const rateLimit    = require('express-rate-limit');
const fs           = require('fs');
const path         = require('path');
const crypto       = require('crypto');
const { v4: uuid } = require('uuid');
const cron         = require('node-cron');
const sanitizeHtml = require('sanitize-html');
const nodemailer   = require('nodemailer');

const app  = express();
const PORT = process.env.PORT || 3000;
const LETTERS_FILE = path.join(__dirname, 'letters.json');
const LETTER_TTL_HOURS = parseInt(process.env.LETTER_TTL_HOURS || '72', 10);

/* ── Ensure DB file ─────────────────────────────────── */
if (!fs.existsSync(LETTERS_FILE)) fs.writeFileSync(LETTERS_FILE, '{}', 'utf8');

/* ── Middleware ─────────────────────────────────────── */
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "script-src": [
          "'self'",
          "'unsafe-inline'",          // allows inline <script> in HTML
          "https://cdn.jsdelivr.net"  // confetti.min.js CDN
        ],
        "style-src": [
          "'self'",
          "'unsafe-inline'",          // inline <style> blocks
          "https://fonts.googleapis.com"
        ],
        "font-src": [
          "'self'",
          "https://fonts.gstatic.com"
        ]
      }
    }
  })
);

app.use(rateLimit({ windowMs: 60 * 60 * 1000, max: 50 }));
app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

/* ── Helpers ────────────────────────────────────────── */
const readLetters = () => JSON.parse(fs.readFileSync(LETTERS_FILE, 'utf8'));
const saveLetters = (obj) => fs.writeFileSync(LETTERS_FILE, JSON.stringify(obj, null, 2));
const hash = (s) => crypto.createHash('sha256').update(s).digest('hex');

/* ── Routes ─────────────────────────────────────────── */

// Create a new letter
app.post('/create-letter', async (req, res) => {
  try {
    const { message = '', passphrase = '', email = '' } = req.body;
    const clean = sanitizeHtml(message.trim(), { allowedTags: [], allowedAttributes: {} });
    if (!clean) return res.status(400).json({ error: 'Message cannot be empty.' });

    const id = uuid().slice(0, 6);
    const db = readLetters();
    db[id] = { msg: clean, hash: passphrase ? hash(passphrase) : null, created: Date.now() };
    saveLetters(db);

    const link = `${req.protocol}://${req.get('host')}/view/${id}`;
    if (email) await sendEmail(email, link, clean).catch(console.error);

    res.json({ link });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal error' });
  }
});

// Pretty reader page
app.get('/view/:id', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'view.html'));
});

// Legacy redirect (/letter/:id → /view/:id)
app.get('/letter/:id', (req, res) => {
  res.redirect(`/view/${req.params.id}`);
});

// API: fetch letter JSON
app.post('/get-letter/:id', (req, res) => {
  const { passphrase = '' } = req.body;
  const db  = readLetters();
  const rec = db[req.params.id];
  if (!rec) return res.status(404).json({ error: 'Letter not found' });
  if (rec.hash && rec.hash !== hash(passphrase))
    return res.status(401).json({ error: 'Wrong passphrase' });
  res.json({ message: rec.msg });
});

/* ── Email helper ──────────────────────────────────── */
async function sendEmail(to, link, msg) {
  if (!process.env.SMTP_HOST) return;              // skip if SMTP not set
  const transport = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || '465', 10),
    secure: true,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
  });
  await transport.sendMail({
    from: `"Love‑Letter Bot" <${process.env.SMTP_USER}>`,
    to,
    subject: 'You received a love letter 💌',
    html: `<p>Someone sent you a love letter.</p>
           <p><a href="${link}">Read it here</a></p>
           <hr><pre style="font-family:Georgia;">${msg}</pre>`
  });
}

/* ── Auto-delete expired letters ───────────────────── */
cron.schedule('0 * * * *', () => {
  const db = readLetters();
  const cutoff = Date.now() - LETTER_TTL_HOURS * 3600 * 1000;
  let changed = false;
  for (const id of Object.keys(db)) {
    if (db[id].created < cutoff) { delete db[id]; changed = true; }
  }
  if (changed) saveLetters(db);
});

/* ── Launch server ─────────────────────────────────── */
app.listen(PORT, () =>
  console.log(`💌  Love Letter app running → http://localhost:${PORT}`)
);
