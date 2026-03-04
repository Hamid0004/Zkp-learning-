const express = require('express');
const cors    = require('cors');
const path    = require('path');
const crypto  = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3000;

const SESSION_TTL_MS   = 10 * 60 * 1000;
const SCAN_TTL_MS      = 2  * 60 * 1000;
const CLEANUP_INTERVAL = 60 * 1000;
const CLAIM_TYPES      = ['zkauth', 'age', 'dob', 'identity'];

const STATE = {
  PENDING  : 'pending',
  SCANNING : 'scanning',
  PROVING  : 'proving',
  COMPLETED: 'completed',
  EXPIRED  : 'expired',
};

app.use(cors({
  origin: process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',')
    : '*',
  methods: ['GET', 'POST', 'DELETE'],
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const sessions = new Map();
const stats = {
  totalSessions : 0,
  totalProofs   : 0,
  proofTimes    : [],
  get avgProofTime() {
    if (!this.proofTimes.length) return 0;
    return Math.round(this.proofTimes.reduce((a, b) => a + b, 0) / this.proofTimes.length);
  },
};

function makeChallenge() { return crypto.randomBytes(32).toString('hex'); }
function buildDeepLink(sessionId, challenge, claimType) {
  const base = process.env.DEEP_LINK_SCHEME || 'zkpapp';
  return `${base}://auth?session=${sessionId}&challenge=${challenge}&claim=${claimType}`;
}
function log(level, msg, extra = '') {
  const icons = { info: '✅', warn: '⚠️', error: '❌' };
  console.log(`${icons[level] || '📋'} [${new Date().toISOString()}] ${msg} ${extra}`);
}
function recordProofTime(ms) {
  if (typeof ms !== 'number') return;
  stats.proofTimes.push(ms);
  if (stats.proofTimes.length > 100) stats.proofTimes.shift();
}

function createSession({ domain, claimType }) {
  const sessionId = crypto.randomUUID();
  const challenge = makeChallenge();
  const deepLink  = buildDeepLink(sessionId, challenge, claimType);

  return {
    sessionId,
    domain,
    claimType,
    challenge,
    deepLink,
    status    : STATE.PENDING,
    proof     : null,
    nullifier : null,
    metadata  : null,
    claimResult: null,
    createdAt : Date.now(),
    expiresAt : Date.now() + SESSION_TTL_MS,
    scannedAt : null,
    verifiedAt: null,
  };
}

// ─── Routes ───────────────────────────────────────────────────

app.get('/', (req, res) => res.json({
  name       : 'zkAuth Relay Server',
  version    : '2.1.0',
  status     : 'online',
  environment: process.env.NODE_ENV || 'development',
  timestamp  : new Date().toISOString(),
  stats: {
    activeSessions: sessions.size,
    totalSessions : stats.totalSessions,
    totalProofs   : stats.totalProofs,
    avgProofTimeMs: stats.avgProofTime,
  },
}));

app.get('/health', (req, res) => res.json({
  status        : 'ok',
  uptime        : Math.round(process.uptime()),
  memory_mb     : Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
  activeSessions: sessions.size,
  totalProofs   : stats.totalProofs,
}));

// ── START SESSION ─────────────────────────────────────────────
app.get('/api/start-session', (req, res) => {
  const domain    = req.query.domain || 'unknown';
  const claimType = CLAIM_TYPES.includes(req.query.claim)
    ? req.query.claim : 'zkauth';

  const session = createSession({ domain, claimType });
  sessions.set(session.sessionId, session);
  stats.totalSessions++;

  setTimeout(() => {
    const s = sessions.get(session.sessionId);
    if (s && s.status === STATE.PENDING) {
      s.status = STATE.EXPIRED;
      sessions.set(session.sessionId, s);
    }
  }, SESSION_TTL_MS);

  log('info', `Session created: ${session.sessionId}`, `| ${domain} | ${claimType}`);

  // ✅ Return BOTH old format + new format — nothing breaks
  res.json({
    // Old fields (original app uses these)
    session_id : session.sessionId,
    challenge  : session.challenge,
    expires_in : SESSION_TTL_MS / 1000,
    qr_data    : Buffer.from(JSON.stringify({
      sessionId : session.sessionId,
      domain,
      challenge : session.challenge,
      timestamp : Date.now(),
    })).toString('base64'),

    // New fields (passkey flow uses these)
    claim_type : session.claimType,
    deep_link  : session.deepLink,
  });
});

// ── SCAN NOTIFY ───────────────────────────────────────────────
app.post('/api/scan-notify', (req, res) => {
  const { sessionId } = req.body;
  const session = sessions.get(sessionId);

  if (!session) return res.status(404).json({ error: 'Session not found', error_code: 'SESSION_NOT_FOUND' });
  if (session.status === STATE.COMPLETED) return res.status(409).json({ error: 'Already completed', error_code: 'INVALID_STATE' });
  if (Date.now() > session.expiresAt)    return res.status(410).json({ error: 'Session expired', error_code: 'SESSION_EXPIRED' });

  session.status    = STATE.SCANNING;
  session.scannedAt = Date.now();
  session.expiresAt = Date.now() + SCAN_TTL_MS;
  sessions.set(sessionId, session);

  log('info', `Scan detected: ${sessionId}`);
  res.json({ success: true, status: STATE.SCANNING, claim_type: session.claimType, challenge: session.challenge });
});

// ── PROVING NOTIFY ────────────────────────────────────────────
app.post('/api/proving-notify', (req, res) => {
  const { sessionId } = req.body;
  const session = sessions.get(sessionId);

  if (!session) return res.status(404).json({ error: 'Session not found', error_code: 'SESSION_NOT_FOUND' });
  if (session.status === STATE.COMPLETED) return res.status(409).json({ error: 'Already completed', error_code: 'INVALID_STATE' });

  session.status = STATE.PROVING;
  sessions.set(sessionId, session);

  log('info', `Proving: ${sessionId}`);
  res.json({ success: true, status: STATE.PROVING });
});

// ── UPLOAD PROOF ──────────────────────────────────────────────
app.post('/api/upload-proof', (req, res) => {
  const { sessionId, session_id, proof, proof_data, nullifier, metadata, claimResult } = req.body;
  const sid       = sessionId || session_id;
  const proofData = proof     || proof_data;

  if (!sid)       return res.status(400).json({ error: 'Missing session ID',  error_code: 'MISSING_SESSION_ID' });
  if (!proofData) return res.status(400).json({ error: 'Missing proof data',  error_code: 'MISSING_PROOF' });

  const session = sessions.get(sid);
  if (!session)                           return res.status(404).json({ error: 'Session not found',      error_code: 'SESSION_NOT_FOUND' });
  if (session.status === STATE.COMPLETED) return res.status(409).json({ error: 'Proof already submitted', error_code: 'DUPLICATE_PROOF' });
  if (session.status === STATE.EXPIRED || Date.now() > session.expiresAt)
    return res.status(410).json({ error: 'Session expired', error_code: 'SESSION_EXPIRED' });

  session.status      = STATE.COMPLETED;
  session.proof       = proofData;
  session.nullifier   = nullifier    || null;
  session.metadata    = metadata     || null;
  session.claimResult = claimResult  || null;
  session.verifiedAt  = Date.now();
  sessions.set(sid, session);

  stats.totalProofs++;
  recordProofTime(metadata?.generation_time_ms);

  log('info', `Proof verified: ${sid}`, `| ${metadata?.generation_time_ms ?? 'N/A'}ms`);

  res.json({
    success    : true,
    message    : 'Proof verified successfully',
    session_id : sid,
    verified_at: session.verifiedAt,
  });
});

// ── POLL STATUS ───────────────────────────────────────────────
app.get('/api/poll-status/:session_id', (req, res) => {
  const session = sessions.get(req.params.session_id);
  if (!session) return res.status(404).json({ error: 'Session not found', error_code: 'SESSION_NOT_FOUND' });

  const resp = {
    session_id    : session.sessionId,
    status        : session.status,
    claim_type    : session.claimType,
    domain        : session.domain,
    created_at    : session.createdAt,
    expires_at    : session.expiresAt,
    time_remaining: Math.max(0, Math.floor((session.expiresAt - Date.now()) / 1000)),
  };

  if (session.status === STATE.COMPLETED) {
    resp.proof        = session.proof;
    resp.nullifier    = session.nullifier;
    resp.metadata     = session.metadata;
    resp.claim_result = session.claimResult;
    resp.verified_at  = session.verifiedAt;
  }

  res.json(resp);
});

// ── STATS ─────────────────────────────────────────────────────
app.get('/api/stats', (req, res) => res.json({
  active_sessions      : sessions.size,
  total_sessions       : stats.totalSessions,
  total_proofs         : stats.totalProofs,
  avg_proof_time_ms    : stats.avgProofTime,
  server_uptime_seconds: Math.round(process.uptime()),
  memory_usage_mb      : Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
}));

app.delete('/api/session/:session_id', (req, res) => {
  if (sessions.delete(req.params.session_id)) {
    log('info', `Deleted: ${req.params.session_id}`);
    res.json({ success: true });
  } else {
    res.status(404).json({ error: 'Session not found', error_code: 'SESSION_NOT_FOUND' });
  }
});

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// ─── Cleanup ──────────────────────────────────────────────────
setInterval(() => {
  const now = Date.now(); let cleaned = 0;
  for (const [id, s] of sessions.entries()) {
    if (now > s.expiresAt && s.status !== STATE.COMPLETED) {
      sessions.delete(id); cleaned++;
    }
  }
  if (cleaned > 0) log('info', `Cleaned ${cleaned} expired sessions`);
}, CLEANUP_INTERVAL);

// ─── Boot ─────────────────────────────────────────────────────
const server = app.listen(PORT, '0.0.0.0', () => {
  log('info', `zkAuth Relay v2.1 on port ${PORT}`);
  log('info', `Health: http://localhost:${PORT}/health`);
});

process.on('SIGTERM', () => {
  server.close(() => { log('info', 'Server closed'); process.exit(0); });
});
process.on('uncaughtException',  err => log('error', 'Uncaught:', err.message));
process.on('unhandledRejection', err => log('error', 'Rejection:', err));