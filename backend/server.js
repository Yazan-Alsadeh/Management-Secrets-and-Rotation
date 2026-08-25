const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const vault = require('node-vault')({
    apiVersion: 'v1',
    // read environment variables for Vault address and token from the environment 
    endpoint: process.env.VAULT_ADDR || 'http://127.0.0.1:8200',
    // read the Vault token from environment variables
    token: process.env.VAULT_TOKEN
});


const FRONTEND_URL = 'https://management-secrets-and-rotation.pages.dev';
const PORT = process.env.PORT || 5000;
const NODE_ENV = 'production';


async function fetchSecretsFromVault() {
    try {
        // path to the secrets in Vault
        
        const path = 'backend/production/db-credentials';
        
        // read the secrets from Vault
        const result = await vault.read(`secret/data/${path}`);
        
        const secrets = result.data.data;
        
        if (!secrets.DB_HOST || !secrets.DB_USER || !secrets.DB_PASSWORD || !secrets.JWT_SECRET) {
            throw new Error('some values are missing in the fetched secrets');
        }

        console.log(' all secrets fetched successfully from Vault');
        return secrets;
    } catch (error) {
        console.error('Error fetching secrets from Vault:', error.message);
        // exit the process if secrets cannot be fetched
        process.exit(1);
    }
}


async function startServer() {
    // 3.1 جلب الأسرار من Vault
    const secrets = await fetchSecretsFromVault();

    const {
        DB_HOST,
        DB_PORT = 5432,
        DB_NAME,
        DB_USER,
        DB_PASSWORD,
        JWT_SECRET
    } = secrets;

    // create a PostgreSQL connection pool
    const pool = new Pool({
        host: DB_HOST,
        port: parseInt(DB_PORT, 10),
        database: DB_NAME,
        user: DB_USER,
        password: DB_PASSWORD,
        ssl: { rejectUnauthorized: false } 
    });

    
    const app = express();
    app.disable('x-powered-by');

    
    app.use(cors({
        origin: FRONTEND_URL,
        methods: ['GET', 'POST'],
        allowedHeaders: ['Content-Type', 'Authorization']
    }));
    app.use(express.json({ limit: '20kb' }));

    
    function createToken(user) {
        return jwt.sign(
            { sub: String(user.id), username: user.username },
            JWT_SECRET, 
            { expiresIn: '1h' }
        );
    }

    
    function requireAuth(req, res, next) {
        const header = req.get('authorization') || '';
        const [scheme, token] = header.split(' ');

        if (scheme !== 'Bearer' || !token) {
            return res.status(401).json({ message: 'Authentication required' });
        }

        try {
            req.auth = jwt.verify(token, JWT_SECRET); 
            return next();
        } catch (_error) {
            return res.status(401).json({ message: 'Invalid or expired token' });
        }
    }

    
    app.get('/health', async (_req, res) => {
        try {
            await pool.query('SELECT 1');
            return res.json({ ok: true, status: 'Server is running' });
        } catch (error) {
            console.error('Health check error:', error.message);
            return res.status(503).json({ ok: false, status: 'Database unavailable' });
        }
    });

    // login endpoint for user authentication
    app.post('/login', async (req, res) => {
        try {
            const { username, password } = req.body || {};

            if (
                typeof username !== 'string' ||
                typeof password !== 'string' ||
                username.trim().length < 1 ||
                username.length > 100 ||
                password.length < 1 ||
                password.length > 200
            ) {
                return res.status(400).json({ message: 'Invalid username or password' });
            }

            const result = await pool.query(
                `SELECT id, username, password, email, phone, created_at
                 FROM users
                 WHERE username = $1
                 LIMIT 1`,
                [username.trim()]
            );

            const user = result.rows[0];
            if (!user || user.password !== password) {
                return res.status(401).json({ message: 'Invalid username or password' });
            }

            return res.json({
                success: true,
                token: createToken(user),
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    phone: user.phone,
                    created_at: user.created_at
                }
            });
        } catch (error) {
            console.error('Login error:', error.message);
            return res.status(500).json({ message: 'Internal server error' });
        }
    });

    // endpoint to get the authenticated user's profile
    app.get('/api/me', requireAuth, async (req, res) => {
        try {
            const result = await pool.query(
                `SELECT id, username, email, phone, created_at
                 FROM users
                 WHERE id = $1
                 LIMIT 1`,
                [req.auth.sub]
            );

            if (!result.rows[0]) {
                return res.status(404).json({ message: 'User not found' });
            }

            return res.json({ success: true, user: result.rows[0] });
        } catch (error) {
            console.error('Profile error:', error.message);
            return res.status(500).json({ message: 'Internal server error' });
        }
    });

    // endpoint to register a new user
    app.post('/api/register', async (req, res) => {
        try {
            const { username, password, email, phone } = req.body || {};

            if (
                typeof username !== 'string' || username.trim().length < 3 || username.length > 100 ||
                typeof password !== 'string' || password.length < 8 || password.length > 200 ||
                typeof email !== 'string' || email.trim().length < 3 || email.length > 255
            ) {
                return res.status(400).json({ message: 'Invalid registration data' });
            }

            const passwordHash = await bcrypt.hash(password, 12);
            const result = await pool.query(
                `INSERT INTO users (username, password_hash, email, phone)
                 VALUES ($1, $2, $3, $4)
                 RETURNING id, username, email, phone, created_at`,
                [username.trim(), passwordHash, email.trim(), phone || null]
            );

            return res.status(201).json({ success: true, user: result.rows[0] });
        } catch (error) {
            if (error.code === '42703') {
                return res.status(503).json({ message: 'Password migration is not completed yet' });
            }
            if (error.code === '23505') {
                return res.status(409).json({ message: 'Username or email already exists' });
            }
            console.error('Registration error:', error.message);
            return res.status(500).json({ message: 'Internal server error' });
        }
    });

    
    app.use((_req, res) => {
        res.status(404).json({ message: 'Not found' });
    });

    app.use((error, _req, res, _next) => {
        console.error('Unhandled error:', error.message);
        res.status(500).json({ message: 'Internal server error' });
    });

    app.listen(PORT, '0.0.0.0', () => {
        console.log(`🚀 Backend running on port ${PORT}`);
        console.log(`🌍 Environment: ${NODE_ENV}`);
        console.log(`🔒 Secrets loaded from Vault successfully!`);
    });
}


startServer();
