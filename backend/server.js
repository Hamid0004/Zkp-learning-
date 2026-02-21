const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const sessions = new Map();
const stats = {
    totalSessions: 0,
    totalProofs: 0,
    averageProofTime: 0,
    proofTimes: []
};

console.log("🚀 zkAuth Relay Server Starting...");
console.log(`📡 Environment: ${process.env.NODE_ENV || 'development'}`);

app.get('/', (req, res) => {
    res.json({
        name: 'zkAuth Relay Server',
        version: '1.0.0',
        status: 'online',
        environment: process.env.NODE_ENV || 'development',
        timestamp: new Date().toISOString(),
        stats: {
            activeSessions: sessions.size,
            totalSessions: stats.totalSessions,
            totalProofs: stats.totalProofs
        }
    });
});

app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        activeSessions: sessions.size,
        totalProofs: stats.totalProofs
    });
});

app.get('/api/start-session', (req, res) => {
    const sessionId = crypto.randomUUID();
    const domain = req.query.domain || 'unknown';
    const challenge = crypto.randomBytes(32).toString('hex');

    const sessionData = {
        sessionId,
        domain,
        challenge,
        status: 'pending',
        proof: null,
        nullifier: null,
        metadata: null,
        createdAt: Date.now(),
        expiresAt: Date.now() + (10 * 60 * 1000)
    };

    sessions.set(sessionId, sessionData);
    stats.totalSessions++;

    console.log(`✅ Session created: ${sessionId} | Domain: ${domain}`);

    setTimeout(() => {
        if (sessions.has(sessionId) && sessions.get(sessionId).status === 'pending') {
            sessions.delete(sessionId);
            console.log(`🗑️ Expired session: ${sessionId}`);
        }
    }, 10 * 60 * 1000);

    res.json({
        session_id: sessionId,
        challenge: challenge,
        expires_in: 600,
        qr_data: Buffer.from(JSON.stringify({
            sessionId,
            domain,
            challenge,
            timestamp: Date.now()
        })).toString('base64')
    });
});

app.post('/api/upload-proof', (req, res) => {
    const sessionId = req.body.sessionId || req.body.session_id;
    const proofData = req.body.proof || req.body.proof_data;
    const nullifier = req.body.nullifier;
    const metadata = req.body.metadata;

    console.log(`📥 Proof upload for session: ${sessionId}`);

    if (!sessionId) {
        console.error('❌ Missing sessionId');
        return res.status(400).json({ 
            error: 'Missing session ID',
            error_code: 'MISSING_SESSION_ID'
        });
    }

    const session = sessions.get(sessionId);

    if (!session) {
        console.error(`❌ Session not found: ${sessionId}`);
        return res.status(404).json({ 
            error: 'Session not found or expired',
            error_code: 'SESSION_NOT_FOUND'
        });
    }

    if (session.status === 'completed') {
        console.error(`❌ Proof already submitted: ${sessionId}`);
        return res.status(409).json({ 
            error: 'Proof already submitted',
            error_code: 'DUPLICATE_PROOF'
        });
    }

    if (!proofData) {
        console.error('❌ Missing proof data');
        return res.status(400).json({ 
            error: 'Missing proof data',
            error_code: 'MISSING_PROOF'
        });
    }

    if (Date.now() > session.expiresAt) {
        sessions.delete(sessionId);
        console.error(`❌ Session expired: ${sessionId}`);
        return res.status(410).json({ 
            error: 'Session expired',
            error_code: 'SESSION_EXPIRED'
        });
    }

    session.status = 'completed';
    session.proof = proofData;
    session.nullifier = nullifier;
    session.metadata = metadata;
    session.verifiedAt = Date.now();

    sessions.set(sessionId, session);
    stats.totalProofs++;

    if (metadata && metadata.generation_time_ms) {
        stats.proofTimes.push(metadata.generation_time_ms);
        if (stats.proofTimes.length > 100) {
            stats.proofTimes.shift();
        }
        stats.averageProofTime = stats.proofTimes.reduce((a, b) => a + b, 0) / stats.proofTimes.length;
    }

    console.log(`✅ Proof verified: ${sessionId} | Time: ${metadata?.generation_time_ms || 'N/A'}ms | Gates: ${metadata?.num_gates || 'N/A'}`);

    res.json({ 
        success: true,
        message: 'Proof verified successfully',
        session_id: sessionId,
        verified_at: session.verifiedAt
    });
});

app.get('/api/poll-status/:session_id', (req, res) => {
    const sessionId = req.params.session_id;
    const session = sessions.get(sessionId);

    if (!session) {
        return res.status(404).json({ 
            error: 'Session not found',
            error_code: 'SESSION_NOT_FOUND'
        });
    }

    const response = {
        session_id: sessionId,
        status: session.status,
        domain: session.domain,
        created_at: session.createdAt,
        expires_at: session.expiresAt,
        time_remaining: Math.max(0, Math.floor((session.expiresAt - Date.now()) / 1000))
    };

    if (session.status === 'completed') {
        response.proof = session.proof;
        response.nullifier = session.nullifier;
        response.metadata = session.metadata;
        response.verified_at = session.verifiedAt;
    }

    res.json(response);
});

app.get('/api/stats', (req, res) => {
    res.json({
        active_sessions: sessions.size,
        total_sessions: stats.totalSessions,
        total_proofs: stats.totalProofs,
        average_proof_time_ms: Math.round(stats.averageProofTime),
        server_uptime_seconds: Math.round(process.uptime()),
        memory_usage_mb: Math.round(process.memoryUsage().heapUsed / 1024 / 1024)
    });
});

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.delete('/api/session/:session_id', (req, res) => {
    const sessionId = req.params.session_id;
    
    if (sessions.delete(sessionId)) {
        console.log(`🗑️ Manually deleted session: ${sessionId}`);
        res.json({ success: true, message: 'Session deleted' });
    } else {
        res.status(404).json({ 
            error: 'Session not found',
            error_code: 'SESSION_NOT_FOUND'
        });
    }
});

setInterval(() => {
    const now = Date.now();
    let cleaned = 0;
    
    for (const [sessionId, session] of sessions.entries()) {
        if (now > session.expiresAt) {
            sessions.delete(sessionId);
            cleaned++;
        }
    }
    
    if (cleaned > 0) {
        console.log(`🧹 Cleaned ${cleaned} expired sessions`);
    }
}, 60 * 1000);

const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`🌐 Health check: http://localhost:${PORT}/health`);
    console.log(`📊 Dashboard: http://localhost:${PORT}/dashboard`);
});

process.on('SIGTERM', () => {
    console.log('SIGTERM received, shutting down gracefully...');
    server.close(() => {
        console.log('Server closed');
        process.exit(0);
    });
});

process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});