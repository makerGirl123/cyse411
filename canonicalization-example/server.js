// server.js
const express = require('express');
const path = require('path');
const fs = require('fs');
const { body, validationResult } = require('express-validator');
const helmet = require('helmet');

const app = express();

// ---------------------------
// GENERAL SETTINGS
// ---------------------------
app.disable("x-powered-by"); // hide Express fingerprint

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

const BASE_DIR = path.resolve(__dirname, 'files');
if (!fs.existsSync(BASE_DIR)) fs.mkdirSync(BASE_DIR, { recursive: true });

// ---------------------------
// SECURITY HEADERS
// ---------------------------

// Helmet CSP + other security headers
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", "data:"],
        fontSrc: ["'self'"],
        frameAncestors: ["'none'"],
        formAction: ["'self'"]
      }
    }
  })
);

// Clickjacking protection
app.use((req, res, next) => {
  res.setHeader("X-Frame-Options", "DENY");
  next();
});

// Prevent MIME-sniffing
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  next();
});

// Cross-origin protections (Spectre / resource isolation)
app.use((req, res, next) => {
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  next();
});

// Permissions policy (restrict browser features)
app.use((req, res, next) => {
  res.setHeader(
    "Permissions-Policy",
    "geolocation=(), camera=(), microphone=(), autoplay=(), clipboard-read=(), clipboard-write=()"
  );
  next();
});

// Safe cache defaults for dynamic content
app.use((req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  next();
});

// ---------------------------
// STATIC FILES (after all headers!)
// ---------------------------
app.use(express.static(path.join(__dirname, 'public')));

// ---------------------------
// HELPERS
// ---------------------------

// Canonicalize and check file path
function resolveSafe(baseDir, userInput) {
  try {
    userInput = decodeURIComponent(userInput);
  } catch (e) {}
  return path.resolve(baseDir, userInput);
}

// ---------------------------
// SECURE ROUTE
// ---------------------------
app.post(
  '/read',
  body('filename')
    .exists().withMessage('filename required')
    .isString()
    .trim()
    .notEmpty().withMessage('filename must not be empty')
    .custom(value => {
      if (value.includes('\0')) throw new Error('Null byte not allowed');
      return true;
    }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });

    const filename = req.body.filename;
    const normalized = resolveSafe(BASE_DIR, filename);

    if (!normalized.startsWith(BASE_DIR + path.sep)) {
      return res.status(403).json({ error: 'Path traversal detected' });
    }

    if (!fs.existsSync(normalized))
      return res.status(404).json({ error: 'File not found' });

    const content = fs.readFileSync(normalized, 'utf8');
    res.json({ path: normalized, content });
  }
);

// ---------------------------
// INTENTIONALLY VULNERABLE ROUTE (demo)
// ---------------------------
app.post('/read-no-validate', (req, res) => {
  const filename = req.body.filename || '';
  const joined = path.join(BASE_DIR, filename);

  if (!fs.existsSync(joined))
    return res.status(404).json({ error: 'File not found', path: joined });

  const content = fs.readFileSync(joined, 'utf8');
  res.json({ path: joined, content });
});

// ---------------------------
// SAMPLE FILE SETUP ROUTE
// ---------------------------
app.post('/setup-sample', (req, res) => {
  const samples = {
    'hello.txt': 'Hello from safe file!\n',
    'notes/readme.md': '# Readme\nSample readme file'
  };

  Object.keys(samples).forEach(k => {
    const p = path.resolve(BASE_DIR, k);
    const d = path.dirname(p);
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
    fs.writeFileSync(p, samples[k], 'utf8');
  });

  res.json({ ok: true, base: BASE_DIR });
});

// ---------------------------
// START SERVER
// ---------------------------
if (require.main === module) {
  const port = process.env.PORT || 4000;
  app.listen(port, () => {
    console.log(`Server listening on http://localhost:${port}`);
  });
}

module.exports = app;
