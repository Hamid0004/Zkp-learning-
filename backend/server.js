const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = 3000;

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json({ limit: '50mb' })); 
app.use(express.static(path.join(__dirname, 'public')));

// --- IN-MEMORY DATABASE ---
const sessions = new Map();

console.log("🦁 ZK Relay Server Starting...");

// --- ROUTES ---

// 1. START SESSION
app.get('/api/start-session', (req, res) => {
    const sessionId = crypto.randomUUID();
    
    // Default structure with metadata field
    sessions.set(sessionId, { 
        status: 'pending', 
        proof: null, 
        nullifier: null,
        metadata: null // 🦁 Benchmarking data yahan store hoga
    });
    
    console.log(`🆕 Session Created: ${sessionId}`);
    
    setTimeout(() => {
        if (sessions.has(sessionId)) {
            sessions.delete(sessionId);
            console.log(`🗑️ Auto-deleted expired session: ${sessionId}`);
        }
    }, 10 * 60 * 1000); 

    res.json({ session_id: sessionId });
});

// 2. UPLOAD PROOF (Updated for Benchmarking)
app.post('/api/upload-proof', (req, res) => {
    const sessionId = req.body.sessionId || req.body.session_id;
    const proofData = req.body.proof || req.body.proof_data;
    const nullifier = req.body.nullifier;
    const metadata = req.body.metadata; // 🦁 NEW: Receiving Benchmark Metadata (Time, Gates, etc.)

    console.log(`📥 Receiving Proof & Metadata for: ${sessionId}`);

    if (!sessionId || !sessions.has(sessionId)) {
        console.error(`❌ Session Invalid: ${sessionId}`);
        return res.status(404).json({ error: "Session Expired or Invalid" });
    }

    // 🦁 Save Everything including Metadata
    sessions.set(sessionId, { 
        status: 'completed', 
        proof: proofData,
        nullifier: nullifier,
        metadata: metadata // <--- Store it here!
    });
    
    console.log(`✅ Verified! Proof Time: ${metadata ? metadata.generation_time_ms : 'N/A'}ms`);
    res.json({ success: true });
});

// 3. CHECK STATUS
app.get('/api/poll-status/:session_id', (req, res) => {
    const sessionId = req.params.session_id;
    const session = sessions.get(sessionId);

    if (!session) {
        return res.status(404).json({ error: "Session Not Found" });
    }

    // Return status, proof, nullifier, and metadata to the website
    res.json(session);
});

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.listen(PORT, () => {
    console.log(`🚀 Relay Server running on http://localhost:${PORT}`);
});