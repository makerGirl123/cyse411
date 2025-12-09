const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const bcrypt = require("bcrypt");

const app = express();
const PORT = 3001;

// ---------------- SECURITY HEADERS ----------------

// Hide Express fingerprint
app.disable("x-powered-by");

// Serve static assets FIRST so headers apply AFTER
app.use(express.static("public"));

// Apply CSP and other security headers to ALL routes (including static)
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; frame-ancestors 'none'; form-action 'self'; object-src 'none'"
  );
  next();
});

app.use((req, res, next) => {
  res.setHeader(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=()"
  );
  next();
});

// Prevent caching of sensitive content
app.use((req, res, next) => {
  res.setHeader(
    "Cache-Control",
    "no-cache, no-store, must-revalidate, private"
  );
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  next();
});

// ---------------- APP MIDDLEWARE ----------------
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

// ---------------- USER AUTH LOGIC ----------------
const users = [
  {
    id: 1,
    username: "student",
    passwordHash: bcrypt.hashSync("password123", 12)
  }
];

// In-memory session store
const sessions = {}; // token -> { userId }

// Helper: find user by username
function findUser(username) {
  return users.find((u) => u.username === username);
}

// ---------------- ROUTES ----------------

// Check current user session
app.get("/api/me", (req, res) => {
  const token = req.cookies.session;
  if (!token || !sessions[token]) {
    return res.status(401).json({ authenticated: false });
  }

  const session = sessions[token];
  const user = users.find((u) => u.id === session.userId);

  res.json({ authenticated: true, username: user.username });
});

// Login route
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const user = findUser(username);

  if (!user) {
    return res
      .status(401)
      .json({ success: false, message: "Invalid username or password" });
  }

  const match = bcrypt.compareSync(password, user.passwordHash);
  if (!match) {
    return res
      .status(401)
      .json({ success: false, message: "Invalid username or password" });
  }

  // Invalidate any existing session for this user
  for (const t in sessions) {
    if (sessions[t].userId === user.id) {
      delete sessions[t];
    }
  }

  // Create session token
  const token = crypto.randomBytes(32).toString("hex");

  // 10 minute expiration
  const sessionDurationMs = 10 * 60 * 1000;
  sessions[token] = { userId: user.id, expires: Date.now() + sessionDurationMs };

  res.cookie("session", token, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    maxAge: sessionDurationMs
  });

  res.json({ success: true });
});

// Logout route
app.post("/api/logout", (req, res) => {
  const token = req.cookies.session;
  if (token && sessions[token]) {
    delete sessions[token];
  }
  res.clearCookie("session");
  res.json({ success: true });
});

// ---------------- START SERVER ----------------
app.listen(PORT, () => {
  console.log(`FastBank Auth Lab running at http://localhost:${PORT}`);
});
