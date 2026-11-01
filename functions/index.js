const { onRequest } = require('firebase-functions/v2/https');
const { initializeApp } = require('firebase-admin/app');
const { getDatabase } = require('firebase-admin/database');
const crypto = require('crypto');

initializeApp({
  databaseURL: 'https://developer-70f89-default-rtdb.firebaseio.com'
});

const db = getDatabase();
const SIX_HOURS_MS = 6 * 60 * 60 * 1000;

// Replace these three values before deploying.
const DEFAULTS = {
  createdBy: 'Bellalk121',
  createdByEmail: 'bellalk121@gmail.com',
  contactLink: 'https://t.me/Bellalk121'
};

function json(res, code, body) {
  return res.status(code).json(body);
}

function cors(req, res) {
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.set('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.status(204).send('');
    return true;
  }

  if (req.method !== 'POST') {
    json(res, 405, { ok: false, error: 'POST required' });
    return true;
  }

  return false;
}

function randomCredential(length = 8) {
  const chars =
    'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';

  const bytes = crypto.randomBytes(length);

  return Array.from(
    bytes,
    byte => chars[byte % chars.length]
  ).join('');
}

// Creates: firebase/{username}
exports.createKey = onRequest(async (req, res) => {
  if (cors(req, res)) return;

  try {
    let username = null;
    let ref = null;

    // Generate a unique username.
    for (let i = 0; i < 8; i++) {
      const candidate = randomCredential(6);
      const candidateRef = db.ref(`firebase/${candidate}`);
      const exists = await candidateRef.get();

      if (!exists.exists()) {
        username = candidate;
        ref = candidateRef;
        break;
      }
    }

    if (!username || !ref) {
      return json(res, 503, {
        ok: false,
        error: 'Please try again.'
      });
    }

    const password = randomCredential(10);

    // Dynamic values.
    const isActive = req.body?.isActive !== false;

    const selectedDevice = String(
      req.body?.selectedDevice ?? '1'
    );

    const suppliedCredit = Number(
      req.body?.creditUsed ?? 1
    );

    const creditUsed =
      Number.isFinite(suppliedCredit) && suppliedCredit >= 0
        ? suppliedCredit
        : 1;

    // Exact 11-field Firebase record.
    const record = {
      username: username,
      password: password,
      status: isActive ? 'active' : 'inactive',
      validity: 'null',
      access: selectedDevice,
      device: 'null',
      rgtime: 'null',
      creditUsed: creditUsed,
      createdBy: DEFAULTS.createdBy,
      createdByEmail: DEFAULTS.createdByEmail,
      contactLink: DEFAULTS.contactLink
    };

    await ref.set(record);

    return json(res, 200, {
      ok: true,
      username: username,
      password: password,
      status: record.status
    });

  } catch (error) {
    console.error('createKey error:', error);

    return json(res, 500, {
      ok: false,
      error: 'Could not generate key.'
    });
  }
});

// Login: six-hour session.
exports.login = onRequest(async (req, res) => {
  if (cors(req, res)) return;

  try {
    const username = String(
      req.body?.username || ''
    ).trim();

    const password = String(
      req.body?.password || ''
    );

    if (
      !username ||
      !password ||
      username.includes('/') ||
      username.includes('.')
    ) {
      return json(res, 401, {
        ok: false,
        error: 'Invalid credentials.'
      });
    }

    const snap = await db.ref(`firebase/${username}`).get();

    if (!snap.exists()) {
      return json(res, 401, {
        ok: false,
        error: 'Invalid credentials.'
      });
    }

    const record = snap.val();

    if (
      record.status !== 'active' ||
      record.password !== password
    ) {
      return json(res, 401, {
        ok: false,
        error: 'Invalid credentials or inactive key.'
      });
    }

    const token = crypto.randomBytes(32).toString('base64url');

    const tokenHash = crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');

    const expiresAt = Date.now() + SIX_HOURS_MS;

    await db.ref(`sessions/${tokenHash}`).set({
      username,
      expiresAt
    });

    return json(res, 200, {
      ok: true,
      sessionToken: token,
      expiresAt: expiresAt
    });

  } catch (error) {
    console.error('login error:', error);

    return json(res, 500, {
      ok: false,
      error: 'Login service error.'
    });
  }
});

// Validate session.
exports.validateSession = onRequest(async (req, res) => {
  if (cors(req, res)) return;

  try {
    const token = String(
      req.body?.sessionToken || ''
    );

    if (!token) {
      return json(res, 401, { ok: false });
    }

    const hash = crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');

    const ref = db.ref(`sessions/${hash}`);
    const snap = await ref.get();

    if (!snap.exists()) {
      return json(res, 401, { ok: false });
    }

    const session = snap.val();

    if (Date.now() >= Number(session.expiresAt || 0)) {
      await ref.remove();

      return json(res, 401, { ok: false });
    }

    return json(res, 200, {
      ok: true,
      username: session.username,
      expiresAt: session.expiresAt
    });

  } catch (error) {
    console.error('validateSession error:', error);

    return json(res, 500, { ok: false });
  }
});

// Logout.
exports.logout = onRequest(async (req, res) => {
  if (cors(req, res)) return;

  try {
    const token = String(
      req.body?.sessionToken || ''
    );

    if (token) {
      const hash = crypto
        .createHash('sha256')
        .update(token)
        .digest('hex');

      await db.ref(`sessions/${hash}`).remove();
    }

    return json(res, 200, { ok: true });

  } catch (error) {
    console.error('logout error:', error);

    return json(res, 500, { ok: false });
  }
});