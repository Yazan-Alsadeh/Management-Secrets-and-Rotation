const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const DB_HOST = 'dpg-da63b30jo6nc73e82hkg-a.singapore-postgres.render.com';
const DB_PORT = 5432;
const DB_NAME = 'postgres1_g8qj';
const DB_USER = 'postgres1';
const DB_PASSWORD = 'xXJgW6baw56oSmXJDH6XiocAsy3Jdj1v';
const JWT_SECRET = 'U8BQCisA5XDefVgVKqTQzROW40QUND8L5YYdxRO6xUMWGkFwTiifWPrQOcYklhj';
const FRONTEND_URL = 'https://management-secrets-and-rotation.pages.dev';
const PORT = process.env.PORT || 5000;
const NODE_ENV = 'production';

if (JWT_SECRET === 'PASTE_LONG_RANDOM_JWT_SECRET_HERE') {
  throw new Error('Change JWT_SECRET before starting the server');
}

const app = express();
app.disable('x-powered-by');

const pool = new Pool({
  host: DB_HOST,
  port: DB_PORT,
  database: DB_NAME,
  user: DB_USER,
  password: DB_PASSWORD,
  ssl: { rejectUnauthorized: false }
});

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

    // This route expects the future password_hash column.
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
  console.log(`Backend running on port ${PORT}`);
  console.log(`Environment: ${NODE_ENV}`);
  console.log(`Database: ${DB_HOST}:${DB_PORT}/${DB_NAME}`);
});
