// server.js
const express = require('express');
const path = require('path');
const fs = require('fs');
const { body, validationResult } = require('express-validator');

const app = express();

// ---------------------------
// SECURITY HEADERS
// ---------------------------

// Hide Express fingerprint
app.disable("x-powered-by");

// Content Security Policy
app.use((req, res, next) => {
  res.setHeader("Content-Security-Policy", 
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; form-action 'self'"
  );
  next();
});

// Prevent clickjacking
app.use((req, res, next) => {
  res.setHeader("X-Frame-Options", "DENY");
  next();
});

// Prevent MIME-sniffing
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  next();
});

// Reduce attack surface (Spectre, cross-origin leaks)
app.use((req, res, next) => {
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  next();
});

// Restrict browser features
app.use((req, res, next) => {
  res.setHeader(
    "Permissions-Policy",
    "geolocation=(), camera=(), microphone=(), autoplay=(), clipboard-read=(), clipboard-write=()"
  );
  next();
});

// Safe defaults for dynamic responses
app.use((req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  next();
});

// ---------------------------
// NORMAL APP CONFIG
// ---------------------------

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const BASE_DIR = path.resolve(__dirname, 'files');
if (!fs.existsSync(BASE_DIR)) fs.mkdirSync(BASE_DIR, { recursive: true });

// Canonicalize & check
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
// INTENTIONALLY VULNERABLE ROUTE
// ---------------------------

app.post('/read-no-validate', (req, res) => {
  const filename = req.body.filename || '';

  // Resolve canonical path
  const resolved = path.resolve(BASE_DIR, filename);


  // Check that it is nested inside BASE_DIR
  if (!resolved.startsWith(BASE_DIR + path.sep)) {
    return res.status(403).json({ error: 'Path traversal detected' });
  }


  if (!fs.existsSync(resolved)) {
    return res.status(404).json({ error: 'File not found', path: resolved });
  }





  const content = fs.readFileSync(resolved, 'utf8');
  res.json({ path: resolved, content });

});


// ---------------------------
// SAMPLE SETUP ROUTE
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
