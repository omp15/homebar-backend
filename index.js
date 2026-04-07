require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const rateLimit = require('express-rate-limit');

const app = express();

// CORS — restrict to ALLOWED_ORIGIN in production
const allowedOrigin = process.env.ALLOWED_ORIGIN || 'http://localhost:3000';
app.use(cors({
  origin: allowedOrigin,
  credentials: true,
}));

app.use(express.json({ limit: '10kb' }));

const pool = process.env.DATABASE_URL
  ? new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } })
  : new Pool({ user: 'ompaithankar', host: 'localhost', database: 'homebar', password: '', port: 5432 });

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20,
  message: { error: 'Too many attempts, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

// ── Auth middleware ─────────────────────────────────────────────────────────
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid token' });
  }
  try {
    req.user = jwt.verify(header.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token expired or invalid' });
  }
}

// ── DB init ─────────────────────────────────────────────────────────────────
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id          SERIAL PRIMARY KEY,
      email       TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      bar_name    TEXT NOT NULL DEFAULT 'My Bar',
      user_name   TEXT NOT NULL DEFAULT '',
      unit_pref   TEXT NOT NULL DEFAULT 'oz',
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS bar_ingredients (
      id          SERIAL PRIMARY KEY,
      user_id     INTEGER REFERENCES users(id) ON DELETE CASCADE,
      name        TEXT NOT NULL,
      category    TEXT NOT NULL DEFAULT 'Other',
      UNIQUE(user_id, name)
    );

    CREATE TABLE IF NOT EXISTS cocktails (
      id          SERIAL PRIMARY KEY,
      name        TEXT NOT NULL UNIQUE,
      popularity  INTEGER DEFAULT 999,
      glass       TEXT,
      method      TEXT,
      steps       TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS cocktail_ingredients (
      id            SERIAL PRIMARY KEY,
      cocktail_id   INTEGER REFERENCES cocktails(id) ON DELETE CASCADE,
      ingredient    TEXT NOT NULL,
      amount        TEXT,
      is_garnish    BOOLEAN DEFAULT FALSE
    );

    CREATE TABLE IF NOT EXISTS tried_log (
      id            SERIAL PRIMARY KEY,
      user_id       INTEGER REFERENCES users(id) ON DELETE CASCADE,
      cocktail_name TEXT NOT NULL,
      first_tried   TIMESTAMPTZ DEFAULT NOW(),
      times_made    INTEGER DEFAULT 1,
      UNIQUE(user_id, cocktail_name)
    );

    CREATE TABLE IF NOT EXISTS tasting_notes (
      id            SERIAL PRIMARY KEY,
      user_id       INTEGER REFERENCES users(id) ON DELETE CASCADE,
      cocktail_name TEXT NOT NULL,
      note          TEXT,
      rating        INTEGER CHECK (rating BETWEEN 1 AND 5),
      created_at    TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS share_links (
      id          SERIAL PRIMARY KEY,
      user_id     INTEGER REFERENCES users(id) ON DELETE CASCADE,
      token       TEXT NOT NULL UNIQUE,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // Seed cocktails from file if DB is empty
  const { rows } = await pool.query('SELECT COUNT(*) FROM cocktails');
  if (parseInt(rows[0].count) === 0) {
    const COCKTAILS = require('./cocktails-seed.js');
    for (const c of COCKTAILS) {
      const { rows: inserted } = await pool.query(
        `INSERT INTO cocktails (name, popularity, glass, method, steps)
         VALUES ($1, $2, $3, $4, $5) RETURNING id`,
        [c.name, c.popularity, c.glass, c.method, c.steps]
      );
      const cid = inserted[0].id;
      for (const r of c.recipe) {
        await pool.query(
          `INSERT INTO cocktail_ingredients (cocktail_id, ingredient, amount, is_garnish)
           VALUES ($1, $2, $3, $4)`,
          [cid, r.ingredient, r.amount, r.is_garnish]
        );
      }
    }
    console.log(`Seeded ${COCKTAILS.length} cocktails.`);
  }
}

// ── Health ───────────────────────────────────────────────────────────────────
app.get('/', (_req, res) => res.json({ status: 'ok', message: 'Home Bar API running' }));

// ── Auth routes ──────────────────────────────────────────────────────────────
app.post('/api/auth/register', authLimiter, async (req, res) => {
  const { email, password, bar_name, user_name } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

  const hash = await bcrypt.hash(password, 10);
  try {
    const { rows } = await pool.query(
      `INSERT INTO users (email, password_hash, bar_name, user_name)
       VALUES ($1, $2, $3, $4) RETURNING id, email, bar_name, user_name, unit_pref`,
      [email.toLowerCase().trim(), hash, bar_name || 'My Bar', user_name || '']
    );
    const user = rows[0];
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    res.status(201).json({ token, user });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Email already registered' });
    throw err;
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });

  const { rows } = await pool.query(
    'SELECT * FROM users WHERE email = $1',
    [email.toLowerCase().trim()]
  );
  const user = rows[0];
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
  const { password_hash, ...safeUser } = user;
  res.json({ token, user: safeUser });
});

// ── Profile ──────────────────────────────────────────────────────────────────
app.get('/api/profile', auth, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id, email, bar_name, user_name, unit_pref, created_at FROM users WHERE id = $1',
    [req.user.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'User not found' });
  res.json(rows[0]);
});

app.put('/api/profile', auth, async (req, res) => {
  const { bar_name, user_name, unit_pref } = req.body;
  const { rows } = await pool.query(
    `UPDATE users SET
       bar_name  = COALESCE($1, bar_name),
       user_name = COALESCE($2, user_name),
       unit_pref = COALESCE($3, unit_pref)
     WHERE id = $4
     RETURNING id, email, bar_name, user_name, unit_pref`,
    [bar_name, user_name, unit_pref, req.user.id]
  );
  res.json(rows[0]);
});

// ── Cocktails ────────────────────────────────────────────────────────────────
app.get('/api/cocktails', async (_req, res) => {
  const { rows: cocktails } = await pool.query(
    'SELECT * FROM cocktails ORDER BY popularity'
  );
  const { rows: ingredients } = await pool.query(
    'SELECT * FROM cocktail_ingredients'
  );

  const map = {};
  for (const i of ingredients) {
    if (!map[i.cocktail_id]) map[i.cocktail_id] = [];
    map[i.cocktail_id].push(i);
  }

  res.json(cocktails.map(c => ({ ...c, recipe: map[c.id] || [] })));
});

app.get('/api/cocktails/:id', async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM cocktails WHERE id = $1', [req.params.id]);
  if (!rows[0]) return res.status(404).json({ error: 'Not found' });

  const { rows: recipe } = await pool.query(
    'SELECT * FROM cocktail_ingredients WHERE cocktail_id = $1',
    [req.params.id]
  );
  res.json({ ...rows[0], recipe });
});

// ── Bar inventory (per-user) ──────────────────────────────────────────────────
app.get('/api/bar', auth, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT * FROM bar_ingredients WHERE user_id = $1 ORDER BY category, name',
    [req.user.id]
  );
  res.json(rows);
});

app.post('/api/bar', auth, async (req, res) => {
  const { name, category } = req.body;
  if (!name) return res.status(400).json({ error: 'name is required' });

  try {
    const { rows } = await pool.query(
      `INSERT INTO bar_ingredients (user_id, name, category)
       VALUES ($1, $2, $3) RETURNING *`,
      [req.user.id, name.trim(), category || 'Other']
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Already in your bar' });
    throw err;
  }
});

app.delete('/api/bar/:id', auth, async (req, res) => {
  await pool.query(
    'DELETE FROM bar_ingredients WHERE id = $1 AND user_id = $2',
    [req.params.id, req.user.id]
  );
  res.json({ success: true });
});

// Bulk sync — replace entire bar in one call (useful for initial load from local state)
app.put('/api/bar/sync', auth, async (req, res) => {
  const { ingredients } = req.body; // [{ name, category }]
  if (!Array.isArray(ingredients)) return res.status(400).json({ error: 'ingredients array required' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM bar_ingredients WHERE user_id = $1', [req.user.id]);
    for (const { name, category } of ingredients) {
      if (!name) continue;
      await client.query(
        `INSERT INTO bar_ingredients (user_id, name, category) VALUES ($1, $2, $3)
         ON CONFLICT (user_id, name) DO NOTHING`,
        [req.user.id, name.trim(), category || 'Other']
      );
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }

  const { rows } = await pool.query(
    'SELECT * FROM bar_ingredients WHERE user_id = $1 ORDER BY category, name',
    [req.user.id]
  );
  res.json(rows);
});

// ── Cocktail suggestions (uses authenticated user's bar) ─────────────────────
app.get('/api/cocktails/suggestions', auth, async (req, res) => {
  const { rows: barRows } = await pool.query(
    'SELECT name FROM bar_ingredients WHERE user_id = $1',
    [req.user.id]
  );
  const barItems = new Set(barRows.map(r => r.name.toLowerCase()));

  const { rows: cocktails } = await pool.query('SELECT * FROM cocktails ORDER BY popularity');
  const { rows: allIngredients } = await pool.query('SELECT * FROM cocktail_ingredients');

  const recipeMap = {};
  for (const i of allIngredients) {
    if (!recipeMap[i.cocktail_id]) recipeMap[i.cocktail_id] = [];
    recipeMap[i.cocktail_id].push(i);
  }

  const results = cocktails.map(c => {
    const recipe = recipeMap[c.id] || [];
    const required = recipe.filter(i => !i.is_garnish);
    const have = required.filter(i => barItems.has(i.ingredient.toLowerCase()));
    const missing = required.filter(i => !barItems.has(i.ingredient.toLowerCase()));
    const canMake = missing.length === 0;
    const matchScore = required.length > 0 ? have.length / required.length : 1;
    return { ...c, recipe, canMake, matchScore, haveRequired: have.length, totalRequired: required.length, missingRequired: missing.map(i => i.ingredient) };
  });

  results.sort((a, b) => {
    if (a.canMake !== b.canMake) return a.canMake ? -1 : 1;
    return b.matchScore - a.matchScore;
  });

  res.json(results);
});

// ── Tried log ────────────────────────────────────────────────────────────────
app.get('/api/tried', auth, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT * FROM tried_log WHERE user_id = $1 ORDER BY first_tried DESC',
    [req.user.id]
  );
  res.json(rows);
});

app.post('/api/tried/:cocktailName', auth, async (req, res) => {
  const name = decodeURIComponent(req.params.cocktailName);
  const { rows } = await pool.query(
    `INSERT INTO tried_log (user_id, cocktail_name, first_tried, times_made)
     VALUES ($1, $2, NOW(), 1)
     ON CONFLICT (user_id, cocktail_name) DO UPDATE
       SET times_made = tried_log.times_made + 1
     RETURNING *`,
    [req.user.id, name]
  );
  res.json(rows[0]);
});

app.delete('/api/tried/:cocktailName', auth, async (req, res) => {
  const name = decodeURIComponent(req.params.cocktailName);
  await pool.query(
    'DELETE FROM tried_log WHERE user_id = $1 AND cocktail_name = $2',
    [req.user.id, name]
  );
  res.json({ success: true });
});

// ── Tasting notes ────────────────────────────────────────────────────────────
app.get('/api/notes', auth, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT * FROM tasting_notes WHERE user_id = $1 ORDER BY created_at DESC',
    [req.user.id]
  );
  res.json(rows);
});

app.get('/api/notes/:cocktailName', auth, async (req, res) => {
  const name = decodeURIComponent(req.params.cocktailName);
  const { rows } = await pool.query(
    'SELECT * FROM tasting_notes WHERE user_id = $1 AND cocktail_name = $2 ORDER BY created_at DESC',
    [req.user.id, name]
  );
  res.json(rows);
});

app.post('/api/notes/:cocktailName', auth, async (req, res) => {
  const name = decodeURIComponent(req.params.cocktailName);
  const { note, rating } = req.body;
  if (rating !== undefined && (rating < 1 || rating > 5)) {
    return res.status(400).json({ error: 'rating must be 1–5' });
  }

  const { rows } = await pool.query(
    `INSERT INTO tasting_notes (user_id, cocktail_name, note, rating)
     VALUES ($1, $2, $3, $4) RETURNING *`,
    [req.user.id, name, note || null, rating || null]
  );
  res.status(201).json(rows[0]);
});

app.delete('/api/notes/:noteId', auth, async (req, res) => {
  await pool.query(
    'DELETE FROM tasting_notes WHERE id = $1 AND user_id = $2',
    [req.params.noteId, req.user.id]
  );
  res.json({ success: true });
});

// Upsert — update the most recent note for this cocktail, or create one
app.put('/api/notes/:cocktailName', auth, async (req, res) => {
  const name = decodeURIComponent(req.params.cocktailName);
  const { note, rating } = req.body;
  if (rating !== undefined && (rating < 1 || rating > 5)) {
    return res.status(400).json({ error: 'rating must be 1–5' });
  }

  // Find most recent existing note for this user+cocktail
  const { rows } = await pool.query(
    `SELECT id FROM tasting_notes WHERE user_id = $1 AND cocktail_name = $2
     ORDER BY created_at DESC LIMIT 1`,
    [req.user.id, name]
  );

  if (rows[0]) {
    const { rows: updated } = await pool.query(
      `UPDATE tasting_notes SET note = $1, rating = $2 WHERE id = $3 RETURNING *`,
      [note || null, rating || null, rows[0].id]
    );
    return res.json(updated[0]);
  }

  const { rows: created } = await pool.query(
    `INSERT INTO tasting_notes (user_id, cocktail_name, note, rating) VALUES ($1, $2, $3, $4) RETURNING *`,
    [req.user.id, name, note || null, rating || null]
  );
  res.status(201).json(created[0]);
});

// ── Social / sharing ─────────────────────────────────────────────────────────
const crypto = require('crypto');

// Generate a share link for your public bar
app.post('/api/share/bar', auth, async (req, res) => {
  // Reuse existing token if one exists, otherwise create one
  const existing = await pool.query(
    'SELECT token FROM share_links WHERE user_id = $1',
    [req.user.id]
  );
  if (existing.rows[0]) return res.json({ token: existing.rows[0].token });

  const token = crypto.randomBytes(12).toString('hex');
  await pool.query(
    'INSERT INTO share_links (user_id, token) VALUES ($1, $2)',
    [req.user.id, token]
  );
  res.json({ token });
});

// Public view of a shared bar (no auth required)
app.get('/api/share/:token', async (req, res) => {
  const { rows: linkRows } = await pool.query(
    'SELECT user_id FROM share_links WHERE token = $1',
    [req.params.token]
  );
  if (!linkRows[0]) return res.status(404).json({ error: 'Share link not found' });

  const userId = linkRows[0].user_id;
  const [profileRes, barRes] = await Promise.all([
    pool.query('SELECT bar_name, user_name FROM users WHERE id = $1', [userId]),
    pool.query('SELECT name, category FROM bar_ingredients WHERE user_id = $1 ORDER BY category, name', [userId]),
  ]);

  res.json({
    bar_name: profileRes.rows[0]?.bar_name,
    user_name: profileRes.rows[0]?.user_name,
    ingredients: barRes.rows,
  });
});

// View another user's public bar by user ID (same data, different entry point)
app.get('/api/users/:id/bar', async (req, res) => {
  const { rows: linkRows } = await pool.query(
    'SELECT token FROM share_links WHERE user_id = $1',
    [req.params.id]
  );
  if (!linkRows[0]) return res.status(403).json({ error: 'This bar is not public' });

  const [profileRes, barRes] = await Promise.all([
    pool.query('SELECT bar_name, user_name FROM users WHERE id = $1', [req.params.id]),
    pool.query('SELECT name, category FROM bar_ingredients WHERE user_id = $1 ORDER BY category, name', [req.params.id]),
  ]);

  res.json({
    bar_name: profileRes.rows[0]?.bar_name,
    user_name: profileRes.rows[0]?.user_name,
    ingredients: barRes.rows,
    share_token: linkRows[0].token,
  });
});

// ── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 5500;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  initDB().catch(err => { console.error('DB init failed:', err); process.exit(1); });
});
