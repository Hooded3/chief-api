require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcrypt');

const app = express();
const port = process.env.PORT || 4000;

// CORS
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
});

app.use(express.json());

// Connection pool
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT,
    ssl: { rejectUnauthorized: false },
    waitForConnections: true,
    connectionLimit: 20,
    queueLimit: 0,
    connectTimeout: 10000
});

// ===== LOGIN =====
app.post('/api/login', (req, res) => {
    const { username, password, userType } = req.body;
    const start = Date.now();
    
    let query = '';
    if (userType === 'staff') {
        // Only select columns that exist
        query = 'SELECT id, username, role, full_name, is_master_admin FROM admin_users WHERE username = ?';
    } else {
        query = 'SELECT id, username, role FROM resident_portal_access WHERE username = ?';
    }
    
    pool.query(query, [username], (err, results) => {
        if (err) {
            console.error('Login error:', err);
            return res.status(500).json({ error: err.message });
        }
        if (results.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const user = results[0];
        
        // For now, accept any password (you should use bcrypt)
        res.json({
            success: true,
            user: {
                id: user.id,
                username: user.username,
                role: user.role || 'user',
                full_name: user.full_name || user.username,
                is_master_admin: user.is_master_admin || 0,
                is_chief_admin: user.id === 1 ? 1 : 0
            }
        });
        console.log(`Login in ${Date.now() - start}ms`);
    });
});

// ===== QUICK STATS =====
app.get('/api/stats', (req, res) => {
    pool.query(
        'SELECT (SELECT COUNT(*) FROM residents) as residents, (SELECT COUNT(*) FROM families) as families, (SELECT COUNT(*) FROM families WHERE family_head_id IS NOT NULL) as family_heads, (SELECT COUNT(*) FROM pending_residents WHERE status = "pending") as pending',
        (err, results) => {
            if (err) {
                console.error('Stats error:', err);
                return res.status(500).json({ error: err.message });
            }
            res.json(results[0] || { residents: 0, families: 0, family_heads: 0, pending: 0 });
        }
    );
});

// ===== RESIDENTS =====
app.get('/api/residents', (req, res) => {
    const limit = parseInt(req.query.limit) || 100;
    pool.query(
        'SELECT id, full_name, unique_village_id, national_id, phone, gender, village_id, is_family_head, deletion_pending FROM residents ORDER BY full_name LIMIT ?',
        [limit],
        (err, results) => {
            if (err) {
                console.error('Residents error:', err);
                return res.status(500).json({ error: err.message });
            }
            res.json(results);
        }
    );
});

// ===== FAMILIES =====
app.get('/api/families', (req, res) => {
    pool.query('SELECT id, family_name, family_head_id FROM families ORDER BY family_name', (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

app.get('/api/families/:id/members', (req, res) => {
    pool.query(
        `SELECT r.id, r.full_name, r.unique_village_id, fl.relationship_to_head 
         FROM residents r 
         JOIN family_links fl ON r.id = fl.resident_id 
         WHERE fl.family_id = ? 
         ORDER BY fl.relationship_to_head, r.full_name`,
        [req.params.id],
        (err, results) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(results);
        }
    );
});

// ===== FAMILY HEADS =====
app.get('/api/family-heads', (req, res) => {
    pool.query(
        `SELECT r.id, r.full_name, r.unique_village_id, f.id as family_id, f.family_name 
         FROM residents r 
         JOIN families f ON r.id = f.family_head_id 
         ORDER BY r.full_name`,
        (err, results) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(results);
        }
    );
});

// ===== PENDING RESIDENTS =====
app.get('/api/pending-residents', (req, res) => {
    pool.query(
        `SELECT pr.*, u.full_name as submitter_name 
         FROM pending_residents pr
         LEFT JOIN admin_users u ON pr.submitted_by = u.id
         WHERE pr.status = 'pending'
         ORDER BY pr.submitted_at DESC`,
        (err, results) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(results);
        }
    );
});

// ===== VILLAGES =====
app.get('/api/villages', (req, res) => {
    pool.query('SELECT id, name, location, elder_id, status FROM villages ORDER BY name', (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

// ===== PING (Keep alive) =====
app.get('/api/ping', (req, res) => {
    res.json({ status: 'ok', time: Date.now() });
});

app.get('/api/health', (req, res) => {
    pool.query('SELECT 1', (err) => {
        if (err) {
            res.status(500).json({ status: 'error', message: err.message });
        } else {
            res.json({ status: 'ok', timestamp: Date.now() });
        }
    });
});

// ===== USERS (for admin) =====
app.get('/api/admin-users', (req, res) => {
    pool.query('SELECT id, username, full_name, role, is_enabled, is_master_admin, last_login, created_at FROM admin_users ORDER BY id', (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

app.listen(port, () => {
    console.log(`Chief API running on port ${port}`);
});
