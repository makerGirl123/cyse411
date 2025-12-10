const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const bcrypt = require("bcrypt");

const app = express();
const PORT = 3001;

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

// Hide Express fingerprint
app.disable('x-powered-by');

// CSP header
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; frame-ancestors 'none'; form-action 'self'; object-src 'none'; base-uri 'self'"
  );
  next();
});

// Permissions Policy header
app.use((req, res, next) => {
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  next();
});

// Cache control for sensitive endpoints
app.use('/api', (req, res, next) => {
  res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate, private");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  next();
});

// Serve public files with caching
app.use(express.static("public", { maxAge: '1d' }));

// Users (fake database)
const users = [
  {
    id: 1,
    username: "student",
    passwordHash: bcrypt.hashSync("password123", 12)
  }
];

// In-memory session store: token -> { userId, expires, csrfToken }
const sessions = {};

// Helper: find user
function findUser(username) {
  return users.find(u => u.username === username);
}

// CSRF verification middleware
function verifyCsrf(req, res, next) {
  const token = req.cookies.session;
  const session = sessions[token];
  if (!session) return res.status(403).json({ error: "No session" });

  // check CSRF token from header or body
  const requestToken = req.headers['x-csrf-token'] || req.body._csrf;
  if (!requestToken || requestToken !== session.csrfToken) {
    return res.status(403).json({ error: "Invalid CSRF token" });
  }

  next();
}

// Home API: check who is logged in
app.get("/api/me", (req, res) => {
  const token = req.cookies.session;
  if (!token || !sessions[token]) {
    return res.status(401).json({ authenticated: false });
  }
  const session = sessions[token];
  const user = users.find(u => u.id === session.userId);
  res.json({ authenticated: true, username: user.username, csrfToken: session.csrfToken });
});

// Login
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const user = findUser(username);
  if (!user) return res.status(401).json({ success: false, message: "Invalid username or password" });

  const match = bcrypt.compareSync(password, user.passwordHash);
  if (!match) return res.status(401).json({ success: false, message: "Invalid username or password" });

  // Invalidate existing sessions for this user
  for (const t in sessions) {
    if (sessions[t].userId === user.id) {
      delete sessions[t];
    }
  }

  // Create new session
  const token = crypto.randomBytes(32).toString("hex");
  const csrfToken = crypto.randomBytes(32).toString("hex");
  const sessionDurationMs = 10 * 60 * 1000; // 10 minutes

  sessions[token] = { userId: user.id, expires: Date.now() + sessionDurationMs, csrfToken };

  res.cookie("session", token, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    maxAge: sessionDurationMs
  });

  res.json({ success: true, csrfToken });
});

// Logout (CSRF protected)
app.post("/api/logout", verifyCsrf, (req, res) => {
  const token = req.cookies.session;
  if (token && sessions[token]) delete sessions[token];

  res.clearCookie("session");
  res.json({ success: true });
});

// Example protected endpoint
app.post("/api/protected-action", verifyCsrf, (req, res) => {
  res.json({ success: true, message: "Action performed safely!" });
});

// Start server
app.listen(PORT, () => {
  console.log(`FastBank Auth Lab running at http://localhost:${PORT}`);
});
