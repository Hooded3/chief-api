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
    
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    next();
});

app.use(express.json());

// Aiven MySQL connection
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'chief-db-cloud-sangfrankline913-ffce.l.aivencloud.com',
    user: process.env.DB_USER || 'avnadmin',
    password: process.env.DB_PASSWORD || 'your_aiven_password_here',
    database: process.env.DB_NAME || 'chief_db',
    port: process.env.DB_PORT || 18453,
    ssl: { rejectUnauthorized: false },
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

app.get('/', (req, res) => {
    res.json({ message: 'Chief Records API running on Railway!' });
});

app.get('/api/residents', (req, res) => {
    console.log('Fetching residents...');
    const query = 'SELECT id, full_name, unique_village_id, national_id, phone FROM residents ORDER BY full_name LIMIT 100';
    pool.query(query, (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Database error: ' + err.message });
        }
        console.log(`Found ${results.length} residents`);
        res.json(results);
    });
});

app.post('/api/login', (req, res) => {
    const { username, password, userType } = req.body;
    console.log('Login attempt:', username, userType);
    
    let query = '';
    if (userType === 'staff') {
        query = 'SELECT * FROM admin_users WHERE username = ?';
    } else {
        query = 'SELECT * FROM resident_portal_access WHERE username = ?';
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
        bcrypt.compare(password, user.password, (err, result) => {
            if (err) {
                console.error('bcrypt error:', err);
                return res.status(500).json({ error: 'Login error' });
            }
            if (result) {
                res.json({
                    success: true,
                    user: {
                        id: user.id,
                        username: user.username,
                        role: user.role || 'user'
                    }
                });
            } else {
                res.status(401).json({ error: 'Invalid credentials' });
            }
        });
    });
});

app.listen(port, () => {
    console.log(`Chief Records API running on port ${port}`);
    console.log('Connected to Aiven MySQL cloud database!');
});
