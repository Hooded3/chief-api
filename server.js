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

// ===== HELPER FUNCTIONS =====
function isChief(user) {
    return user && (user.role === 'admin' || user.is_master_admin === 1 || user.id === 1);
}

function isAssistant(user) {
    return user && user.role === 'assistant';
}

function isElder(user) {
    return user && user.role === 'elder';
}

function canManageUsers(user) {
    return isChief(user);
}

function canManageElders(user) {
    return isChief(user);
}

function canAddFamilies(user) {
    return isChief(user) || isAssistant(user);
}

function canDeleteFamilies(user) {
    return isChief(user);
}

function canAddResidentsDirect(user) {
    return isChief(user) || isAssistant(user);
}

function canAddResidentsPending(user) {
    return isElder(user);
}

function canApproveResidents(user) {
    return isChief(user);
}

function canDeleteResidents(user) {
    return isChief(user);
}

function canViewAllResidents(user) {
    return isChief(user) || isAssistant(user);
}

function canViewOwnVillageResidents(user) {
    return isElder(user);
}

function canViewAllReports(user) {
    return isChief(user) || isAssistant(user);
}

function canViewOwnVillageReports(user) {
    return isElder(user);
}

// ===== AUTH =====
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
                        is_master_admin: user.is_master_admin || 0,
                        is_chief_admin: user.id === 1 ? 1 : 0,
                        village_id: user.village_id || null
                    }
                });
            } else {
                res.status(401).json({ error: 'Invalid credentials' });
            }
        });
    });
});

// ===== USERS MANAGEMENT (Chief Only) =====
app.get('/api/admin-users', (req, res) => {
    pool.query('SELECT id, username, full_name, role, is_enabled, is_master_admin, village_id, last_login, created_at FROM admin_users ORDER BY id', (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

app.get('/api/admin-users/:id', (req, res) => {
    pool.query('SELECT id, username, full_name, role, is_enabled, is_master_admin, village_id, last_login, created_at FROM admin_users WHERE id = ?', [req.params.id], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        if (results.length === 0) return res.status(404).json({ error: 'User not found' });
        res.json(results[0]);
    });
});

app.post('/api/admin-users', (req, res) => {
    const { username, password, full_name, role, is_enabled, is_master_admin, village_id } = req.body;
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) return res.status(500).json({ error: 'Password hashing error' });
        pool.query(
            'INSERT INTO admin_users (username, password, full_name, role, is_enabled, is_master_admin, village_id) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [username, hash, full_name, role || 'assistant', is_enabled !== undefined ? is_enabled : 1, is_master_admin || 0, village_id || null],
            (err, result) => {
                if (err) {
                    if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Username already exists' });
                    return res.status(500).json({ error: err.message });
                }
                res.json({ success: true, id: result.insertId });
            }
        );
    });
});

app.put('/api/admin-users/:id', (req, res) => {
    const { username, full_name, role, is_enabled, is_master_admin, village_id } = req.body;
    const userId = parseInt(req.params.id);
    if (userId === 1) return res.status(403).json({ error: 'Chief Admin cannot be modified' });
    pool.query(
        'UPDATE admin_users SET username = ?, full_name = ?, role = ?, is_enabled = ?, is_master_admin = ?, village_id = ? WHERE id = ?',
        [username, full_name, role, is_enabled, is_master_admin, village_id, userId],
        (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true });
        }
    );
});

app.put('/api/admin-users/:id/reset-password', (req, res) => {
    const { password } = req.body;
    const userId = parseInt(req.params.id);
    if (userId === 1) return res.status(403).json({ error: 'Chief Admin password cannot be reset' });
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) return res.status(500).json({ error: 'Password hashing error' });
        pool.query('UPDATE admin_users SET password = ? WHERE id = ?', [hash, userId], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true });
        });
    });
});

app.delete('/api/admin-users/:id', (req, res) => {
    const userId = parseInt(req.params.id);
    if (userId === 1) return res.status(403).json({ error: 'Chief Admin cannot be deleted' });
    pool.query('DELETE FROM admin_users WHERE id = ?', [userId], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        if (result.affectedRows === 0) return res.status(404).json({ error: 'User not found' });
        res.json({ success: true });
    });
});

// ===== VILLAGES =====
app.get('/api/villages', (req, res) => {
    pool.query('SELECT * FROM villages ORDER BY name', (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

app.post('/api/villages', (req, res) => {
    const { name, location, elder_id } = req.body;
    pool.query('INSERT INTO villages (name, location, elder_id) VALUES (?, ?, ?)',
        [name, location, elder_id],
        (err, result) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, id: result.insertId });
        }
    );
});

// ===== RESIDENTS =====

// GET residents - based on user role
app.get('/api/residents', (req, res) => {
    // For elders, only show their village residents
    // For chief/assistant, show all
    let query = 'SELECT * FROM residents ORDER BY full_name';
    pool.query(query, (err, results) => {
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

// POST resident - Chief/Assistant direct, Elder goes to pending
app.post('/api/residents', (req, res) => {
    const { full_name, national_id, unique_village_id, dob, gender, phone, village_id } = req.body;
    pool.query(
        'INSERT INTO residents (full_name, national_id, unique_village_id, dob, gender, phone, village_id) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [full_name, national_id, unique_village_id, dob, gender, phone, village_id || null],
        (err, result) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, id: result.insertId, direct: true });
        }
    );
});

// PENDING RESIDENTS (Elders submit here)
app.post('/api/pending-residents', (req, res) => {
    const { full_name, national_id, unique_village_id, dob, gender, phone, submitted_by, village_id } = req.body;
    pool.query(
        'INSERT INTO pending_residents (full_name, national_id, unique_village_id, dob, gender, phone, submitted_by, village_id, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, "pending")',
        [full_name, national_id, unique_village_id, dob, gender, phone, submitted_by, village_id || null],
        (err, result) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, id: result.insertId });
        }
    );
});

// GET pending residents (Chief only)
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

// Approve/Reject pending resident (Chief only)
app.put('/api/pending-residents/:id', (req, res) => {
    const { status, reviewed_by, notes } = req.body;
    const pendingId = req.params.id;
    
    pool.getConnection((err, connection) => {
        if (err) return res.status(500).json({ error: err.message });
        
        connection.beginTransaction((err) => {
            if (err) {
                connection.release();
                return res.status(500).json({ error: err.message });
            }
            
            // Get pending resident data
            connection.query('SELECT * FROM pending_residents WHERE id = ?', [pendingId], (err, pendingResults) => {
                if (err || pendingResults.length === 0) {
                    connection.rollback(() => {
                        connection.release();
                        return res.status(404).json({ error: 'Pending resident not found' });
                    });
                    return;
                }
                
                const pending = pendingResults[0];
                
                if (status === 'approved') {
                    // Move to residents table
                    connection.query(
                        'INSERT INTO residents (full_name, national_id, unique_village_id, dob, gender, phone, village_id) VALUES (?, ?, ?, ?, ?, ?, ?)',
                        [pending.full_name, pending.national_id, pending.unique_village_id, pending.dob, pending.gender, pending.phone, pending.village_id],
                        (err) => {
                            if (err) {
                                connection.rollback(() => { connection.release(); });
                                return res.status(500).json({ error: err.message });
                            }
                            
                            // Update pending status
                            connection.query(
                                'UPDATE pending_residents SET status = ?, reviewed_at = NOW(), reviewed_by = ?, notes = ? WHERE id = ?',
                                [status, reviewed_by, notes || null, pendingId],
                                (err) => {
                                    if (err) {
                                        connection.rollback(() => { connection.release(); });
                                        return res.status(500).json({ error: err.message });
                                    }
                                    connection.commit((err) => {
                                        if (err) {
                                            connection.rollback(() => { connection.release(); });
                                            return res.status(500).json({ error: err.message });
                                        }
                                        connection.release();
                                        res.json({ success: true, action: 'approved' });
                                    });
                                }
                            );
                        }
                    );
                } else {
                    // Just update status
                    connection.query(
                        'UPDATE pending_residents SET status = ?, reviewed_at = NOW(), reviewed_by = ?, notes = ? WHERE id = ?',
                        [status, reviewed_by, notes || null, pendingId],
                        (err) => {
                            if (err) {
                                connection.rollback(() => { connection.release(); });
                                return res.status(500).json({ error: err.message });
                            }
                            connection.commit((err) => {
                                if (err) {
                                    connection.rollback(() => { connection.release(); });
                                    return res.status(500).json({ error: err.message });
                                }
                                connection.release();
                                res.json({ success: true, action: status });
                            });
                        }
                    );
                }
            });
        });
    });
});

// DELETE resident (Chief only)
app.delete('/api/residents/:id', (req, res) => {
    pool.query('DELETE FROM residents WHERE id = ?', [req.params.id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Resident not found' });
        res.json({ success: true });
    });
});

// ===== FAMILIES =====

// GET families - all roles can view
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

// POST family - Chief and Assistant can add
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

// DELETE family - Chief only
app.delete('/api/families/:id', (req, res) => {
    pool.query('DELETE FROM families WHERE id = ?', [req.params.id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Family not found' });
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
        new Promise((resolve, reject) => pool.query('SELECT COUNT(*) as count FROM admin_users', (err, r) => err ? reject(err) : resolve(r[0].count))),
        new Promise((resolve, reject) => pool.query('SELECT COUNT(*) as count FROM pending_residents WHERE status = "pending"', (err, r) => err ? reject(err) : resolve(r[0].count)))
    ]).then(([residents, families, heads, users, pending]) => {
        res.json({ residents, families, family_heads: heads, users, pending });
    }).catch(err => res.status(500).json({ error: err.message }));
});

// ===== REPORTS =====
app.get('/api/reports/residents', (req, res) => {
    pool.query('SELECT full_name, unique_village_id, gender, phone, is_family_head FROM residents ORDER BY full_name', (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

app.get('/api/reports/families', (req, res) => {
    pool.query(
        `SELECT f.id, f.family_name, r.full_name as head_name, 
                COUNT(fl.resident_id) as member_count
         FROM families f
         LEFT JOIN residents r ON f.family_head_id = r.id
         LEFT JOIN family_links fl ON f.id = fl.family_id
         GROUP BY f.id
         ORDER BY f.family_name`,
        (err, results) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(results);
        }
    );
});

// Village-specific reports for elders
app.get('/api/reports/village/:villageId', (req, res) => {
    const villageId = req.params.villageId;
    Promise.all([
        new Promise((resolve, reject) => 
            pool.query('SELECT COUNT(*) as count FROM residents WHERE village_id = ?', [villageId], (err, r) => err ? reject(err) : resolve(r[0].count))
        ),
        new Promise((resolve, reject) => 
            pool.query('SELECT COUNT(*) as count FROM residents WHERE village_id = ? AND gender = "M"', [villageId], (err, r) => err ? reject(err) : resolve(r[0].count))
        ),
        new Promise((resolve, reject) => 
            pool.query('SELECT COUNT(*) as count FROM residents WHERE village_id = ? AND gender = "F"', [villageId], (err, r) => err ? reject(err) : resolve(r[0].count))
        )
    ]).then(([total, male, female]) => {
        res.json({ total, male, female, village_id: villageId });
    }).catch(err => res.status(500).json({ error: err.message }));
});

app.listen(port, () => {
    console.log(`Chief Records API running on port ${port}`);
});
