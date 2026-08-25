const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const vaultFactory = require('node-vault');

/* =========================
   Environment configuration
========================= */

const PORT = Number.parseInt(process.env.PORT || '5000', 10);
const NODE_ENV = process.env.NODE_ENV || 'production';
const FRONTEND_URL = process.env.FRONTEND_URL ||
    'https://management-secrets-and-rotation.pages.dev';

const VAULT_ADDR = process.env.VAULT_ADDR;
const VAULT_TOKEN = process.env.VAULT_TOKEN;
const VAULT_NAMESPACE = process.env.VAULT_NAMESPACE || 'admin';
const VAULT_SECRET_PATH = process.env.VAULT_SECRET_PATH ||
    'secret/data/backend/production/db-credentials';

if (!VAULT_ADDR) {
    throw new Error('VAULT_ADDR is not configured');
}

if (!VAULT_TOKEN) {
    throw new Error('VAULT_TOKEN is not configured');
}

/* =========================
   Vault client
========================= */

const vault = vaultFactory({
    apiVersion: 'v1',
    endpoint: VAULT_ADDR,
    token: VAULT_TOKEN,
    namespace: VAULT_NAMESPACE
});

/* =========================
   Read secrets from Vault KV v2
========================= */

async function fetchSecretsFromVault() {
    try {
        // For KV v2, the API path must contain /data/.
        const result = await vault.read(VAULT_SECRET_PATH);
        const secrets = result?.data?.data;

        if (!secrets || typeof secrets !== 'object') {
            throw new Error(
                `Vault returned no secret data for ${VAULT_SECRET_PATH}`
            );
        }

        const requiredKeys = [
            'DB_HOST',
            'DB_NAME',
            'DB_USER',
            'DB_PASSWORD',
            'JWT_SECRET'
        ];

        const missingKeys = requiredKeys.filter((key) => {
            return secrets[key] === undefined ||
                secrets[key] === null ||
                String(secrets[key]).trim() === '';
        });

        if (missingKeys.length > 0) {
            throw new Error(
                `Missing required Vault keys: ${missingKeys.join(', ')}`
            );
        }

        console.log('Vault secrets loaded successfully');
        return secrets;
    } catch (error) {
        console.error('Vault read failed:', {
            message: error.message,
            statusCode: error.response?.statusCode || error.response?.status,
            path: VAULT_SECRET_PATH,
            namespace: VAULT_NAMESPACE
        });

        throw error;
    }
}

/* =========================
   Application startup
========================= */

async function startServer() {
    const secrets = await fetchSecretsFromVault();

    const {
        DB_HOST,
        DB_PORT = '5432',
        DB_NAME,
        DB_USER,
        DB_PASSWORD,
        JWT_SECRET
    } = secrets;

    const parsedDbPort = Number.parseInt(String(DB_PORT), 10);

    if (!Number.isInteger(parsedDbPort) || parsedDbPort < 1 || parsedDbPort > 65535) {
        throw new Error(`Invalid DB_PORT value: ${DB_PORT}`);
    }

    if (String(JWT_SECRET).length < 32) {
        throw new Error('JWT_SECRET must contain at least 32 characters');
    }

    const pool = new Pool({
        host: String(DB_HOST),
        port: parsedDbPort,
        database: String(DB_NAME),
        user: String(DB_USER),
        password: String(DB_PASSWORD),
        // Set PGSSL_REJECT_UNAUTHORIZED=false only if your provider requires it.
        ssl: {
            rejectUnauthorized:
                process.env.PGSSL_REJECT_UNAUTHORIZED !== 'false'
        }
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
            {
                sub: String(user.id),
                username: user.username
            },
            String(JWT_SECRET),
            { expiresIn: '1h' }
        );
    }

    function requireAuth(req, res, next) {
        const header = req.get('authorization') || '';
        const [scheme, token] = header.split(' ');

        if (scheme !== 'Bearer' || !token) {
            return res.status(401).json({
                message: 'Authentication required'
            });
        }

        try {
            req.auth = jwt.verify(token, String(JWT_SECRET));
            return next();
        } catch (_error) {
            return res.status(401).json({
                message: 'Invalid or expired token'
            });
        }
    }

    /* =========================
       Health endpoint
    ========================= */

    app.get('/health', async (_req, res) => {
        try {
            await pool.query('SELECT 1');
            return res.json({
                ok: true,
                status: 'Server is running'
            });
        } catch (error) {
            console.error('Health check error:', error.message);
            return res.status(503).json({
                ok: false,
                status: 'Database unavailable'
            });
        }
    });

    /* =========================
       Login
    ========================= */

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
                return res.status(400).json({
                    message: 'Invalid username or password'
                });
            }

            const result = await pool.query(
                `SELECT id, username, password_hash, email, phone, created_at
                 FROM users
                 WHERE username = $1
                 LIMIT 1`,
                [username.trim()]
            );

            const user = result.rows[0];
            const passwordIsValid = user
                ? await bcrypt.compare(password, user.password_hash)
                : false;

            if (!user || !passwordIsValid) {
                return res.status(401).json({
                    message: 'Invalid username or password'
                });
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
            return res.status(500).json({
                message: 'Internal server error'
            });
        }
    });

    /* =========================
       Current user profile
    ========================= */

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
                return res.status(404).json({
                    message: 'User not found'
                });
            }

            return res.json({
                success: true,
                user: result.rows[0]
            });
        } catch (error) {
            console.error('Profile error:', error.message);
            return res.status(500).json({
                message: 'Internal server error'
            });
        }
    });

    /* =========================
       Register user
    ========================= */

    app.post('/api/register', async (req, res) => {
        try {
            const { username, password, email, phone } = req.body || {};

            if (
                typeof username !== 'string' ||
                username.trim().length < 3 ||
                username.length > 100 ||
                typeof password !== 'string' ||
                password.length < 8 ||
                password.length > 200 ||
                typeof email !== 'string' ||
                email.trim().length < 3 ||
                email.length > 255
            ) {
                return res.status(400).json({
                    message: 'Invalid registration data'
                });
            }

            const passwordHash = await bcrypt.hash(password, 12);

            const result = await pool.query(
                `INSERT INTO users
                    (username, password_hash, email, phone)
                 VALUES ($1, $2, $3, $4)
                 RETURNING id, username, email, phone, created_at`,
                [
                    username.trim(),
                    passwordHash,
                    email.trim(),
                    phone || null
                ]
            );

            return res.status(201).json({
                success: true,
                user: result.rows[0]
            });
        } catch (error) {
            if (error.code === '42703') {
                return res.status(503).json({
                    message: 'Password migration is not completed yet'
                });
            }

            if (error.code === '23505') {
                return res.status(409).json({
                    message: 'Username or email already exists'
                });
            }

            console.error('Registration error:', error.message);
            return res.status(500).json({
                message: 'Internal server error'
            });
        }
    });

    /* =========================
       404 and error handlers
    ========================= */

    app.use((_req, res) => {
        return res.status(404).json({
            message: 'Not found'
        });
    });

    app.use((error, _req, res, _next) => {
        console.error('Unhandled error:', error.message);
        return res.status(500).json({
            message: 'Internal server error'
        });
    });

    const server = app.listen(PORT, '0.0.0.0', () => {
        console.log(`Backend running on port ${PORT}`);
        console.log(`Environment: ${NODE_ENV}`);
        console.log('Secrets loaded from Vault successfully');
    });

    const shutdown = async (signal) => {
        console.log(`${signal} received. Shutting down...`);

        server.close(async () => {
            await pool.end();
            process.exit(0);
        });
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
}

startServer().catch((error) => {
    console.error('Server startup failed:', error.message);
    process.exit(1);
});
