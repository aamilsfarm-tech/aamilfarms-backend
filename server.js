"use strict";
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const COLS = ["ponds", "entries"];
const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const USER_RE = /^[a-z0-9._-]{3,32}$/;

async function initDb(pool) {
  await pool.query(`CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'staff',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS docs (
    col TEXT NOT NULL,
    id TEXT NOT NULL,
    data JSONB NOT NULL DEFAULT '{}',
    deleted BOOLEAN NOT NULL DEFAULT false,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (col, id)
  )`);
  await pool.query("CREATE INDEX IF NOT EXISTS docs_updated_idx ON docs (updated_at)");
}

async function seedOwner(pool, env) {
  const { rows } = await pool.query("SELECT count(*)::int AS n FROM users");
  if (rows[0].n > 0) return;
  const u = (env.OWNER_USERNAME || "").trim().toLowerCase();
  const p = env.OWNER_PASSWORD || "";
  if (!USER_RE.test(u) || p.length < 8) {
    console.warn("No users exist. Set OWNER_USERNAME (3-32 chars: a-z 0-9 . _ -) and OWNER_PASSWORD (8+ chars) to create the owner login.");
    return;
  }
  await pool.query("INSERT INTO users (username, name, hash, role) VALUES ($1, $2, $3, 'owner')", [u, env.OWNER_NAME || "Owner", await bcrypt.hash(p, 10)]);
  console.log("Owner account created:", u);
}

function createApp(pool, env) {
  env = env || process.env;
  const secret = env.JWT_SECRET;
  if (!secret) throw new Error("JWT_SECRET is required");
  const app = express();
  app.set("trust proxy", 1);
  app.disable("x-powered-by");
  app.use(express.json({ limit: "64kb" }));
  const allowed = (env.FRONTEND_ORIGIN || "").split(",").map((x) => x.trim().replace(/\/$/, "")).filter(Boolean);
  app.use((req, res, next) => {
    const o = req.headers.origin;
    if (o && (allowed.includes("*") || allowed.includes(o))) {
      res.set("Access-Control-Allow-Origin", o);
      res.set("Vary", "Origin");
      res.set("Access-Control-Allow-Headers", "Authorization, Content-Type");
      res.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
      res.set("Access-Control-Max-Age", "86400");
    }
    if (req.method === "OPTIONS") return res.status(204).end();
    next();
  });
  app.use((req, res, next) => {
    res.set("X-Content-Type-Options", "nosniff");
    res.set("Referrer-Policy", "same-origin");
    next();
  });

  // --- login throttle (per IP, in memory) ---
  const fails = new Map();
  function throttled(ip) {
    const r = fails.get(ip);
    return r && r.n >= 8 && Date.now() - r.t < 10 * 60 * 1000;
  }
  function noteFail(ip) {
    const r = fails.get(ip);
    if (!r || Date.now() - r.t > 10 * 60 * 1000) fails.set(ip, { n: 1, t: Date.now() });
    else r.n++;
  }

  function tokenFor(u) {
    return jwt.sign({ uid: u.id }, secret, { expiresIn: "60d" });
  }
  async function auth(req, res, next) {
    try {
      const m = /^Bearer (.+)$/.exec(req.headers.authorization || "");
      const tok = m && m[1];
      if (!tok) return res.status(401).json({ error: "auth" });
      const { uid } = jwt.verify(tok, secret);
      const { rows } = await pool.query("SELECT id, username, name, role FROM users WHERE id = $1", [uid]);
      if (!rows[0]) return res.status(401).json({ error: "auth" });
      req.user = rows[0];
      next();
    } catch (e) {
      res.status(401).json({ error: "auth" });
    }
  }
  function owner(req, res, next) {
    if (req.user.role !== "owner") return res.status(403).json({ error: "owner_only" });
    next();
  }
  const wrap = (fn) => (req, res) => fn(req, res).catch((e) => { console.error(e); res.status(500).json({ error: "server" }); });

  app.get("/healthz", (req, res) => res.send("ok"));

  // --- auth ---
  app.post("/api/login", wrap(async (req, res) => {
    if (throttled(req.ip)) return res.status(429).json({ error: "too_many" });
    const username = String((req.body && req.body.username) || "").trim().toLowerCase();
    const password = String((req.body && req.body.password) || "");
    const { rows } = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
    const u = rows[0];
    if (!u || !(await bcrypt.compare(password, u.hash))) { noteFail(req.ip); return res.status(401).json({ error: "bad_login" }); }
    fails.delete(req.ip);
    res.json({ token: tokenFor(u), user: { id: u.id, username: u.username, name: u.name, role: u.role } });
  }));
    app.get("/api/me", auth, (req, res) => res.json({ user: req.user }));
  app.post("/api/me/password", auth, wrap(async (req, res) => {
    const oldp = String((req.body && req.body.oldPassword) || ""), newp = String((req.body && req.body.newPassword) || "");
    if (newp.length < 8) return res.status(400).json({ error: "short_password" });
    const { rows } = await pool.query("SELECT hash FROM users WHERE id = $1", [req.user.id]);
    if (!rows[0] || !(await bcrypt.compare(oldp, rows[0].hash))) return res.status(401).json({ error: "bad_login" });
    await pool.query("UPDATE users SET hash = $1 WHERE id = $2", [await bcrypt.hash(newp, 10), req.user.id]);
    res.json({ ok: true });
  }));

  // --- team (owner only) ---
  app.get("/api/users", auth, owner, wrap(async (req, res) => {
    const { rows } = await pool.query("SELECT id, username, name, role FROM users ORDER BY id");
    res.json({ users: rows });
  }));
  app.post("/api/users", auth, owner, wrap(async (req, res) => {
    const b = req.body || {};
    const username = String(b.username || "").trim().toLowerCase();
    const password = String(b.password || "");
    if (!USER_RE.test(username)) return res.status(400).json({ error: "bad_username" });
    if (password.length < 8) return res.status(400).json({ error: "short_password" });
    const ex = await pool.query("SELECT 1 FROM users WHERE username = $1", [username]);
    if (ex.rows[0]) return res.status(409).json({ error: "exists" });
    const r = await pool.query("INSERT INTO users (username, name, hash, role) VALUES ($1, $2, $3, 'staff') RETURNING id, username, name, role", [username, String(b.name || "").slice(0, 80), await bcrypt.hash(password, 10)]);
    res.json({ user: r.rows[0] });
  }));
  app.put("/api/users/:id/password", auth, owner, wrap(async (req, res) => {
    const newp = String((req.body && req.body.password) || "");
    if (newp.length < 8) return res.status(400).json({ error: "short_password" });
    await pool.query("UPDATE users SET hash = $1 WHERE id = $2", [await bcrypt.hash(newp, 10), parseInt(req.params.id, 10)]);
    res.json({ ok: true });
  }));
  app.delete("/api/users/:id", auth, owner, wrap(async (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (id === req.user.id) return res.status(400).json({ error: "self" });
    await pool.query("DELETE FROM users WHERE id = $1", [id]);
    res.json({ ok: true });
  }));

  // --- data sync ---
  app.get("/api/sync", auth, wrap(async (req, res) => {
    const nowRow = await pool.query("SELECT now() AS now");
    const since = req.query.since ? new Date(req.query.since) : new Date(0);
    if (isNaN(since.getTime())) return res.status(400).json({ error: "bad_since" });
    const { rows } = await pool.query("SELECT col, id, data, deleted FROM docs WHERE updated_at >= $1 ORDER BY updated_at", [since.toISOString()]);
    res.json({ now: new Date(nowRow.rows[0].now).toISOString(), docs: rows });
  }));
  app.put("/api/docs/:col/:id", auth, wrap(async (req, res) => {
    const { col, id } = req.params;
    if (!COLS.includes(col) || !ID_RE.test(id)) return res.status(400).json({ error: "bad_path" });
    const data = req.body && req.body.data;
    if (!data || typeof data !== "object" || Array.isArray(data)) return res.status(400).json({ error: "bad_data" });
    if (col === "ponds" && req.user.role !== "owner") return res.status(403).json({ error: "owner_only" });
    if (col === "entries" && !ID_RE.test(String(data.pondId || ""))) return res.status(400).json({ error: "bad_data" });
    await pool.query(
      "INSERT INTO docs (col, id, data, deleted, updated_at) VALUES ($1, $2, $3::jsonb, false, now()) ON CONFLICT (col, id) DO UPDATE SET data = EXCLUDED.data, deleted = false, updated_at = now()",
      [col, id, JSON.stringify(data)]
    );
    res.json({ ok: true });
  }));
  app.delete("/api/docs/:col/:id", auth, wrap(async (req, res) => {
    const { col, id } = req.params;
    if (!COLS.includes(col) || !ID_RE.test(id)) return res.status(400).json({ error: "bad_path" });
    if (col === "ponds" && req.user.role !== "owner") return res.status(403).json({ error: "owner_only" });
    await pool.query("UPDATE docs SET deleted = true, data = '{}'::jsonb, updated_at = now() WHERE col = $1 AND id = $2", [col, id]);
    if (col === "ponds") {
      await pool.query("UPDATE docs SET deleted = true, data = '{}'::jsonb, updated_at = now() WHERE col = 'entries' AND deleted = false AND data->>'pondId' = $1", [id]);
    }
    res.json({ ok: true });
  }));
  app.use("/api", (req, res) => res.status(404).json({ error: "not_found" }));

  app.get("/", (req, res) => res.type("text").send("Aamil Farms API is running."));
  return app;
}

module.exports = { createApp, initDb, seedOwner };

if (require.main === module) {
  (async () => {
    const { Pool } = require("pg");
    const url = process.env.DATABASE_URL;
    if (!url) throw new Error("DATABASE_URL is required");
    const pool = new Pool({ connectionString: url, ssl: /\.render\.com/.test(url) ? { rejectUnauthorized: false } : false });
    await initDb(pool);
    await seedOwner(pool, process.env);
    const port = process.env.PORT || 3000;
    createApp(pool, process.env).listen(port, () => console.log("Pond Ledger listening on", port));
  })().catch((e) => { console.error(e); process.exit(1); });
}
