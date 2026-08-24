const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');

// Configuration constants (replace with your actual values)
const DB_HOST ='dpg-da63b30jo6nc73e82hkg-a.singapore-postgres.render.com';
const DB_PORT = 5432;
const DB_NAME = 'postgres1_g8qj';
const DB_USER ='postgres1';
const DB_PASSWORD ='xXJgW6baw56oSmXJDH6XiocAsy3Jdj1v';
const JWT_SECRET = 'U8BQCisA5XDefVgVKqTQzROW40QUND8L5YYdxRO6xUMWGkFwTiifWPr/QOcYklhj';
const FRONTEND_URL = 'http://localhost:5500';
const PORT = 5000;
const NODE_ENV = 'development';


const app = express();

const pool = new Pool({
  host: DB_HOST,
  port: DB_PORT,
  database: DB_NAME,
  user: DB_USER,
  password: DB_PASSWORD,
  ssl: NODE_ENV === 'production'
    ? { rejectUnauthorized: false }
    : false
});

app.use(cors({
  origin: FRONTEND_URL
}));

app.use(express.json({ limit: '20kb' }));

// Health check: does not expose the database password or API key.
app.get('/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({
      ok: true,
      status: 'Server is running'
    });
  } catch (error) {
    console.error('Health check error:', error.message);
    res.status(503).json({
      ok: false,
      status: 'Database unavailable'
    });
  }
});

// Login compatible with your current table:
// id, username, password, email, phone, created_at
// The current password column is plaintext. Migrate it to bcrypt later.
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
        message: 'Username and password are required'
      });
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
      return res.status(401).json({
        message: 'Invalid username or password'
      });
    }

    // Never return password, DB credentials, API key, or JWT secret.
    return res.json({
      success: true,
      message: 'Login successful',
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

// Register a user in the current schema.
// This keeps compatibility with the existing password column temporarily.
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, email, phone } = req.body || {};

    if (
      typeof username !== 'string' || username.trim().length < 3 || username.length > 100 ||
      typeof password !== 'string' || password.length < 8 || password.length > 200 ||
      typeof email !== 'string' || email.trim().length < 3 || email.length > 255
    ) {
      return res.status(400).json({
        message: 'Invalid registration data'
      });
    }

    const result = await pool.query(
      `INSERT INTO users (username, password, email, phone)
       VALUES ($1, $2, $3, $4)
       RETURNING id, username, email, phone, created_at`,
      [username.trim(), password, email.trim(), phone || null]
    );

    return res.status(201).json({
      success: true,
      message: 'User registered successfully',
      user: result.rows[0]
    });
  } catch (error) {
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

// Safe lookup: does not expose password or SQL query text.
app.get('/api/user/:username', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, username, email, phone, created_at
       FROM users
       WHERE username = $1
       LIMIT 1`,
      [req.params.username]
    );

    if (!result.rows[0]) {
      return res.status(404).json({ message: 'User not found' });
    }

    return res.json({
      success: true,
      user: result.rows[0]
    });
  } catch (error) {
    console.error('User lookup error:', error.message);
    return res.status(500).json({ message: 'Internal server error' });
  }
});

// These intentionally insecure endpoints were removed.
// Do not expose /api/users, /api/system-info, database credentials, or API_KEY.

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
