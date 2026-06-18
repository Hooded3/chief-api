require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 4000;

// CORS middleware
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Session-ID, X-Device-ID');
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

function getClientInfo(req) {
    return {
        ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown',
        userAgent: req.headers['user-agent'] || 'unknown',
        sessionId: req.headers['x-session-id'] || crypto.randomBytes(16).toString('hex'),
        deviceId: req.headers['x-device-id'] || 'unknown'
    };
}

function logActivity(userId, username, action, details, req) {
    const clientInfo = getClientInfo(req);
    pool.query(
        'INSERT INTO activity_log (user_id, username, action, details, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?)',
        [userId, username, action, details, clientInfo.ip, clientInfo.userAgent],
        (err) => { if (err) console.error('Activity log error:', err); }
    );
}

function logLoginHistory(userId, username, success, req, logoutTime = null) {
    const clientInfo = getClientInfo(req);
    pool.query(
        'INSERT INTO login_history (user_id, username, login_time, ip_address, user_agent, success, logout_time, session_id) VALUES (?, ?, NOW(), ?, ?, ?, ?, ?)',
        [userId, username, clientInfo.ip, clientInfo.userAgent, success, logoutTime, clientInfo.sessionId],
        (err) => { if (err) console.error('Login history error:', err); }
    );
}

function logSuspiciousActivity(userId, username, activityType, details, severity, req) {
    const clientInfo = getClientInfo(req);
    pool.query(
        'INSERT INTO suspicious_activities (user_id, username, ip_address, activity_type, details, severity) VALUES (?, ?, ?, ?, ?, ?)',
        [userId, username, clientInfo.ip, activityType, details, severity],
        (err) => { if (err) console.error('Suspicious activity error:', err); }
    );
}

function isChiefAdmin(user) { return user && user.id === 1; }
function isAssistantChief(user) { return user && user.role === 'assistant_chief'; }
function isAdmin(user) { return user && user.role === 'admin'; }
function isElder(user) { return user && user.role === 'elder'; }

function canManageUsers(user) { return isChiefAdmin(user) || isAssistantChief(user) || isAdmin(user); }
function canViewSecurity(user) { return isChiefAdmin(user) || isAssistantChief(user) || isAdmin(user); }

// ===== AUTH =====
app.post('/api/login', (req, res) => {
    const { username, password, userType } = req.body;
    const clientInfo = getClientInfo(req);
    
    // Check for brute force - count failed attempts in last 15 minutes
    pool.query(
        'SELECT COUNT(*) as attempts FROM failed_logins WHERE username = ? AND attempt_time > DATE_SUB(NOW(), INTERVAL 15 MINUTE)',
        [username],
        (err, results) => {
            if (err) return res.status(500).json({ error: err.message });
            if (results[0].attempts >= 5) {
                logSuspiciousActivity(null, username, 'brute_force', `Multiple failed login attempts (${results[0].attempts})`, 'high', req);
                return res.status(429).json({ error: 'Too many failed attempts. Please try again later.' });
            }
            
            let query = userType === 'staff' 
                ? 'SELECT * FROM admin_users WHERE username = ?' 
                : 'SELECT * FROM resident_portal_access WHERE username = ?';
            
            pool.query(query, [username], (err, results) => {
                if (err) return res.status(500).json({ error: err.message });
                
                if (results.length === 0) {
                    // Log failed attempt
                    pool.query('INSERT INTO failed_logins (username, ip_address, user_agent) VALUES (?, ?, ?)',
                        [username, clientInfo.ip, clientInfo.userAgent]);
                    logSuspiciousActivity(null, username, 'failed_login', 'Invalid username attempt', 'low', req);
                    return res.status(401).json({ error: 'Invalid credentials' });
                }
                
                const user = results[0];
                bcrypt.compare(password, user.password, (err, result) => {
                    if (err) return res.status(500).json({ error: 'Login error' });
                    
                    if (result) {
                        // Clear failed attempts
                        pool.query('DELETE FROM failed_logins WHERE username = ?', [username]);
                        
                        // Update last login
                        pool.query('UPDATE admin_users SET last_login = NOW() WHERE id = ?', [user.id]);
                        
                        // Log login history
                        logLoginHistory(user.id, username, true, req);
                        
                        // Track device
                        pool.query(
                            'INSERT INTO user_devices (user_id, device_id, device_name, ip_address, last_used) VALUES (?, ?, ?, ?, NOW()) ON DUPLICATE KEY UPDATE last_used = NOW(), ip_address = ?',
                            [user.id, clientInfo.deviceId, clientInfo.userAgent.substring(0, 50), clientInfo.ip, clientInfo.ip]
                        );
                        
                        // Update session
                        pool.query(
                            'INSERT INTO user_sessions (user_id, session_id, ip_address, user_agent) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE last_activity = NOW(), ip_address = ?',
                            [user.id, clientInfo.sessionId, clientInfo.ip, clientInfo.userAgent, clientInfo.ip]
                        );
                        
                        logActivity(user.id, username, 'Login', 'User logged in successfully', req);
                        
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
                            },
                            sessionId: clientInfo.sessionId
                        });
                    } else {
                        // Log failed attempt
                        pool.query('INSERT INTO failed_logins (username, ip_address, user_agent) VALUES (?, ?, ?)',
                            [username, clientInfo.ip, clientInfo.userAgent]);
                        logSuspiciousActivity(null, username, 'failed_login', 'Invalid password attempt', 'low', req);
                        res.status(401).json({ error: 'Invalid credentials' });
                    }
                });
            });
        }
    );
});

// ===== LOGOUT =====
app.post('/api/logout', (req, res) => {
    const { user_id, session_id } = req.body;
    if (user_id) {
        pool.query('UPDATE user_sessions SET is_active = 0 WHERE user_id = ? AND session_id = ?',
            [user_id, session_id],
            (err) => {
                if (err) console.error('Logout error:', err);
            }
        );
        pool.query('UPDATE login_history SET logout_time = NOW() WHERE user_id = ? AND session_id = ? ORDER BY id DESC LIMIT 1',
            [user_id, session_id],
            (err) => {
                if (err) console.error('Logout history error:', err);
            }
        );
    }
    res.json({ success: true });
});

// ===== SECURITY FEATURES =====

// Get login history
app.get('/api/security/login-history', (req, res) => {
    pool.query(
        'SELECT lh.*, u.full_name FROM login_history lh LEFT JOIN admin_users u ON lh.user_id = u.id ORDER BY lh.login_time DESC LIMIT 100',
        (err, results) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(results);
        }
    );
});

// Get activity log
app.get('/api/security/activity-log', (req, res) => {
    pool.query(
        'SELECT al.*, u.full_name FROM activity_log al LEFT JOIN admin_users u ON al.user_id = u.id ORDER BY al.created_at DESC LIMIT 100',
        (err, results) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(results);
        }
    );
});

// Get suspicious activities
app.get('/api/security/suspicious', (req, res) => {
    pool.query(
        'SELECT sa.*, u.full_name FROM suspicious_activities sa LEFT JOIN admin_users u ON sa.user_id = u.id ORDER BY sa.created_at DESC',
        (err, results) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(results);
        }
    );
});

// Update suspicious activity status
app.put('/api/security/suspicious/:id', (req, res) => {
    const { status, notes, resolved_by } = req.body;
    pool.query(
        'UPDATE suspicious_activities SET status = ?, notes = ?, resolved_at = NOW(), resolved_by = ? WHERE id = ?',
        [status, notes, resolved_by, req.params.id],
        (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true });
        }
    );
});

// Get user sessions
app.get('/api/security/sessions', (req, res) => {
    pool.query(
        'SELECT us.*, u.full_name FROM user_sessions us LEFT JOIN admin_users u ON us.user_id = u.id WHERE us.is_active = 1 ORDER BY us.last_activity DESC',
        (err, results) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(results);
        }
    );
});

// Terminate session
app.delete('/api/security/sessions/:id', (req, res) => {
    pool.query('UPDATE user_sessions SET is_active = 0 WHERE id = ?', [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// Get user devices
app.get('/api/security/devices', (req, res) => {
    pool.query(
        'SELECT ud.*, u.full_name FROM user_devices ud LEFT JOIN admin_users u ON ud.user_id = u.id ORDER BY ud.last_used DESC',
        (err, results) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(results);
        }
    );
});

// Trust/Untrust device
app.put('/api/security/devices/:id', (req, res) => {
    const { is_trusted } = req.body;
    pool.query('UPDATE user_devices SET is_trusted = ? WHERE id = ?', [is_trusted, req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// ===== USERS MANAGEMENT =====
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
                // Create user settings
                pool.query('INSERT INTO user_settings (user_id) VALUES (?)', [result.insertId]);
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
            logActivity(userId, username, 'User Updated', `User ${username} updated their profile`, req);
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
            logActivity(userId, 'system', 'Password Reset', `Password reset for user ID ${userId}`, req);
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
    pool.query('INSERT INTO villages (name, location, elder_id, status) VALUES (?, ?, ?, "pending")',
        [name, location, elder_id],
        (err, result) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, id: result.insertId, status: 'pending' });
        }
    );
});

app.put('/api/villages/:id/approve', (req, res) => {
    const villageId = req.params.id;
    pool.query('UPDATE villages SET status = "approved" WHERE id = ?', [villageId], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

app.put('/api/villages/:id/assign-elder', (req, res) => {
    const { elder_id } = req.body;
    const villageId = req.params.id;
    pool.query('UPDATE villages SET elder_id = ? WHERE id = ?', [elder_id, villageId], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
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
    const { full_name, national_id, unique_village_id, dob, gender, phone, village_id } = req.body;
    pool.query(
        'INSERT INTO residents (full_name, national_id, unique_village_id, dob, gender, phone, village_id) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [full_name, national_id, unique_village_id, dob, gender, phone, village_id || null],
        (err, result) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, id: result.insertId });
        }
    );
});

app.put('/api/residents/:id', (req, res) => {
    const { full_name, national_id, unique_village_id, dob, gender, phone, village_id } = req.body;
    pool.query(
        'UPDATE residents SET full_name = ?, national_id = ?, unique_village_id = ?, dob = ?, gender = ?, phone = ?, village_id = ? WHERE id = ?',
        [full_name, national_id, unique_village_id, dob, gender, phone, village_id, req.params.id],
        (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true });
        }
    );
});

app.delete('/api/residents/:id', (req, res) => {
    const residentId = req.params.id;
    pool.query('UPDATE residents SET deletion_pending = 1, deletion_requested_at = NOW() WHERE id = ?', [residentId], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, pending: true });
    });
});

app.delete('/api/residents/:id/approve', (req, res) => {
    pool.query('DELETE FROM residents WHERE id = ?', [req.params.id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Resident not found' });
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
    const familyId = req.params.id;
    pool.query('UPDATE families SET deletion_pending = 1, deletion_requested_at = NOW() WHERE id = ?', [familyId], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, pending: true });
    });
});

app.delete('/api/families/:id/approve', (req, res) => {
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

app.get('/api/reports/village/:villageId', (req, res) => {
    const villageId = req.params.villageId;
    Promise.all([
        new Promise((resolve, reject) => pool.query('SELECT COUNT(*) as count FROM residents WHERE village_id = ?', [villageId], (err, r) => err ? reject(err) : resolve(r[0].count))),
        new Promise((resolve, reject) => pool.query('SELECT COUNT(*) as count FROM residents WHERE village_id = ? AND gender = "M"', [villageId], (err, r) => err ? reject(err) : resolve(r[0].count))),
        new Promise((resolve, reject) => pool.query('SELECT COUNT(*) as count FROM residents WHERE village_id = ? AND gender = "F"', [villageId], (err, r) => err ? reject(err) : resolve(r[0].count)))
    ]).then(([total, male, female]) => {
        res.json({ total: total.count, male: male.count, female: female.count, village_id: villageId });
    }).catch(err => res.status(500).json({ error: err.message }));
});

// ===== PENDING RESIDENTS =====
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
            
            connection.query('SELECT * FROM pending_residents WHERE id = ?', [pendingId], (err, pendingResults) => {
                if (err || pendingResults.length === 0) {
                    connection.rollback(() => { connection.release(); });
                    return res.status(404).json({ error: 'Pending resident not found' });
                }
                
                const pending = pendingResults[0];
                
                if (status === 'approved') {
                    connection.query(
                        'INSERT INTO residents (full_name, national_id, unique_village_id, dob, gender, phone, village_id) VALUES (?, ?, ?, ?, ?, ?, ?)',
                        [pending.full_name, pending.national_id, pending.unique_village_id, pending.dob, pending.gender, pending.phone, pending.village_id],
                        (err) => {
                            if (err) {
                                connection.rollback(() => { connection.release(); });
                                return res.status(500).json({ error: err.message });
                            }
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

app.listen(port, () => {
    console.log(`Chief Records API running on port ${port}`);
});
