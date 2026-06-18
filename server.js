require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcrypt');

const app = express();
const port = process.env.PORT || 4000;

// CORS middleware
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Credentials', 'true');
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
});

app.use(express.json());

// Aiven MySQL connection
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT,
    ssl: { rejectUnauthorized: false },
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// ===== AUTH & USERS =====

// Login
app.post('/api/login', (req, res) => {
    const { username, password, userType } = req.body;
    let query = userType === 'staff' 
        ? 'SELECT * FROM admin_users WHERE username = ?' 
        : 'SELECT * FROM resident_portal_access WHERE username = ?';
    
    pool.query(query, [username], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        if (results.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
        const user = results[0];
        bcrypt.compare(password, user.password, (err, result) => {
            if (err) return res.status(500).json({ error: 'Login error' });
            if (result) {
                res.json({
                    success: true,
                    user: {
                        id: user.id,
                        username: user.username,
                        role: user.role || 'user',
                        full_name: user.full_name,
                        is_master_admin: user.is_master_admin || 0
                    }
                });
            } else {
                res.status(401).json({ error: 'Invalid credentials' });
            }
        });
    });
});

// Get all admin users (only for master admin)
app.get('/api/admin-users', (req, res) => {
    pool.query('SELECT id, username, full_name, role, is_enabled, is_master_admin, last_login, created_at FROM admin_users ORDER BY id', (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

// Get single admin user
app.get('/api/admin-users/:id', (req, res) => {
    pool.query('SELECT id, username, full_name, role, is_enabled, is_master_admin, last_login, created_at FROM admin_users WHERE id = ?', [req.params.id], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        if (results.length === 0) return res.status(404).json({ error: 'User not found' });
        res.json(results[0]);
    });
});

// Create admin user (only master admin)
app.post('/api/admin-users', (req, res) => {
    const { username, password, full_name, role, is_enabled, is_master_admin } = req.body;
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) return res.status(500).json({ error: 'Password hashing error' });
        pool.query(
            'INSERT INTO admin_users (username, password, full_name, role, is_enabled, is_master_admin) VALUES (?, ?, ?, ?, ?, ?)',
            [username, hash, full_name, role || 'assistant', is_enabled !== undefined ? is_enabled : 1, is_master_admin || 0],
            (err, result) => {
                if (err) {
                    if (err.code === 'ER_DUP_ENTRY') {
                        return res.status(409).json({ error: 'Username already exists' });
                    }
                    return res.status(500).json({ error: err.message });
                }
                res.json({ success: true, id: result.insertId });
            }
        );
    });
});

// Update admin user
app.put('/api/admin-users/:id', (req, res) => {
    const { username, full_name, role, is_enabled, is_master_admin } = req.body;
    pool.query(
        'UPDATE admin_users SET username = ?, full_name = ?, role = ?, is_enabled = ?, is_master_admin = ? WHERE id = ?',
        [username, full_name, role, is_enabled, is_master_admin, req.params.id],
        (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true });
        }
    );
});

// Delete admin user
app.delete('/api/admin-users/:id', (req, res) => {
    pool.query('DELETE FROM admin_users WHERE id = ? AND is_master_admin = 0', [req.params.id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        if (result.affectedRows === 0) {
            return res.status(400).json({ error: 'Cannot delete master admin or user not found' });
        }
        res.json({ success: true });
    });
});

// Reset password
app.put('/api/admin-users/:id/reset-password', (req, res) => {
    const { password } = req.body;
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) return res.status(500).json({ error: 'Password hashing error' });
        pool.query('UPDATE admin_users SET password = ? WHERE id = ?', [hash, req.params.id], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true });
        });
    });
});

// ===== RESIDENTS =====
app.get('/api/residents', (req, res) => {
    pool.query('SELECT * FROM residents ORDER BY full_name', (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

app.get('/api/residents/:id', (req, res) => {
    pool.query('SELECT * FROM residents WHERE id = ?', [req.params.id], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        if (results.length === 0) return res.status(404).json({ error: 'Resident not found' });
        res.json(results[0]);
    });
});

app.post('/api/residents', (req, res) => {
    const { full_name, national_id, unique_village_id, dob, gender, phone } = req.body;
    pool.query(
        'INSERT INTO residents (full_name, national_id, unique_village_id, dob, gender, phone) VALUES (?, ?, ?, ?, ?, ?)',
        [full_name, national_id, unique_village_id, dob, gender, phone],
        (err, result) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, id: result.insertId });
        }
    );
});

app.put('/api/residents/:id', (req, res) => {
    const { full_name, national_id, unique_village_id, dob, gender, phone } = req.body;
    pool.query(
        'UPDATE residents SET full_name = ?, national_id = ?, unique_village_id = ?, dob = ?, gender = ?, phone = ? WHERE id = ?',
        [full_name, national_id, unique_village_id, dob, gender, phone, req.params.id],
        (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true });
        }
    );
});

app.delete('/api/residents/:id', (req, res) => {
    pool.query('DELETE FROM residents WHERE id = ?', [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// ===== FAMILIES =====
app.get('/api/families', (req, res) => {
    pool.query('SELECT * FROM families ORDER BY family_name', (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

app.get('/api/families/:id', (req, res) => {
    pool.query('SELECT * FROM families WHERE id = ?', [req.params.id], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        if (results.length === 0) return res.status(404).json({ error: 'Family not found' });
        res.json(results[0]);
    });
});

app.get('/api/families/:id/members', (req, res) => {
    pool.query(
        `SELECT r.*, fl.relationship_to_head 
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

app.post('/api/families', (req, res) => {
    const { family_head_id, family_name } = req.body;
    pool.query(
        'INSERT INTO families (family_head_id, family_name) VALUES (?, ?)',
        [family_head_id, family_name],
        (err, result) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, id: result.insertId });
        }
    );
});

app.delete('/api/families/:id', (req, res) => {
    pool.query('DELETE FROM families WHERE id = ?', [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// ===== FAMILY LINKS =====
app.post('/api/family-links', (req, res) => {
    const { family_id, resident_id, relationship_to_head } = req.body;
    pool.query(
        'INSERT INTO family_links (family_id, resident_id, relationship_to_head) VALUES (?, ?, ?)',
        [family_id, resident_id, relationship_to_head],
        (err, result) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, id: result.insertId });
        }
    );
});

app.delete('/api/family-links/:id', (req, res) => {
    pool.query('DELETE FROM family_links WHERE id = ?', [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// ===== FAMILY HEADS =====
app.get('/api/family-heads', (req, res) => {
    pool.query(
        `SELECT r.*, f.id as family_id, f.family_name 
         FROM residents r 
         JOIN families f ON r.id = f.family_head_id 
         ORDER BY r.full_name`,
        (err, results) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(results);
        }
    );
});

// ===== STATISTICS =====
app.get('/api/stats', (req, res) => {
    Promise.all([
        new Promise((resolve, reject) => pool.query('SELECT COUNT(*) as count FROM residents', (err, r) => err ? reject(err) : resolve(r[0].count))),
        new Promise((resolve, reject) => pool.query('SELECT COUNT(*) as count FROM families', (err, r) => err ? reject(err) : resolve(r[0].count))),
        new Promise((resolve, reject) => pool.query('SELECT COUNT(*) as count FROM families WHERE family_head_id IS NOT NULL', (err, r) => err ? reject(err) : resolve(r[0].count))),
        new Promise((resolve, reject) => pool.query('SELECT COUNT(*) as count FROM admin_users', (err, r) => err ? reject(err) : resolve(r[0].count)))
    ]).then(([residents, families, heads, users]) => {
        res.json({ residents, families, family_heads: heads, users });
    }).catch(err => res.status(500).json({ error: err.message }));
});

app.listen(port, () => {
    console.log(`Chief Records API running on port ${port}`);
});
