require('dotenv').config();
const express = require('express');
const path = require('path');
const Stripe = require('stripe');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);

const app = express();
const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

const dbConfig = {
  host: process.env.MYSQL_HOST || 'localhost',
  port: Number(process.env.MYSQL_PORT || 3306),
  user: process.env.MYSQL_USER || 'root',
  password: process.env.MYSQL_PASSWORD || '',
  database: process.env.MYSQL_DATABASE || 'dominik_studio'
};

const pool = mysql.createPool({
  ...dbConfig,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  charset: 'utf8mb4'
});

const stripe = process.env.STRIPE_SECRET_KEY ? Stripe(process.env.STRIPE_SECRET_KEY) : null;

const SERVICES = {
  short: 'Krótki film',
  long: 'Dłuższy materiał',
  veryLong: 'Bardzo długi materiał',
  short10: '10 × krótki film',
  long10: '10 × dłuższy materiał',
  veryLong10: '10 × bardzo długi materiał'
};

// Stripe webhook MUST receive the raw request body.
app.post('/api/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripe || !process.env.STRIPE_WEBHOOK_SECRET) {
    return res.status(503).send('Webhook nie jest skonfigurowany.');
  }

  let event;
  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      req.headers['stripe-signature'],
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    console.error('Webhook signature error:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    if (event.type === 'checkout.session.completed') {
      const checkout = event.data.object;
      const orderId = Number(checkout.metadata?.order_id);

      if (orderId) {
        await pool.execute(
          `UPDATE orders
           SET status = 'paid', stripe_payment_intent_id = ?, updated_at = CURRENT_TIMESTAMP
           WHERE id = ?`,
          [checkout.payment_intent || null, orderId]
        );
        console.log(`Zamówienie #${orderId} oznaczone jako OPŁACONE.`);
      }
    }

    if (event.type === 'checkout.session.expired') {
      const checkout = event.data.object;
      const orderId = Number(checkout.metadata?.order_id);
      if (orderId) {
        await pool.execute(
          `UPDATE orders SET status = 'cancelled', updated_at = CURRENT_TIMESTAMP
           WHERE id = ? AND status = 'pending'`,
          [orderId]
        );
      }
    }
  } catch (err) {
    console.error('Webhook database error:', err);
    return res.status(500).send('Webhook database error');
  }

  res.json({ received: true });
});

app.use(express.json());

const sessionStore = new MySQLStore({
  ...dbConfig,
  clearExpired: true,
  checkExpirationInterval: 900000,
  expiration: 1000 * 60 * 60 * 24 * 7,
  createDatabaseTable: true,
  schema: {
    tableName: 'sessions',
    columnNames: {
      session_id: 'session_id',
      expires: 'expires',
      data: 'data'
    }
  }
});

app.use(session({
  name: 'dominik.sid',
  secret: process.env.SESSION_SECRET || 'CHANGE_ME_IN_ENV',
  resave: false,
  saveUninitialized: false,
  store: sessionStore,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
}));

app.use(express.static(path.join(__dirname)));

function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Musisz być zalogowany.' });
  }
  next();
}

function safeUser(user) {
  return { id: user.id, name: user.name, email: user.email, role: user.role };
}

// ---------- AUTH ----------
app.post('/api/register', async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    if (name.length < 2) return res.status(400).json({ error: 'Podaj poprawne imię lub nazwę.' });
    if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Podaj poprawny adres e-mail.' });
    if (password.length < 8) return res.status(400).json({ error: 'Hasło musi mieć minimum 8 znaków.' });

    const [existing] = await pool.execute('SELECT id FROM users WHERE email = ? LIMIT 1', [email]);
    if (existing.length) return res.status(409).json({ error: 'Konto z tym adresem e-mail już istnieje.' });

    const passwordHash = await bcrypt.hash(password, 12);
    const [result] = await pool.execute(
      `INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'client')`,
      [name, email, passwordHash]
    );

    const user = { id: result.insertId, name, email, role: 'client' };
    req.session.user = user;
    res.status(201).json({ user: safeUser(user), redirect: '/dashboard.html' });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Nie udało się utworzyć konta.' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    const [rows] = await pool.execute(
      'SELECT id, name, email, password_hash, role FROM users WHERE email = ? LIMIT 1',
      [email]
    );

    if (!rows.length || !(await bcrypt.compare(password, rows[0].password_hash))) {
      return res.status(401).json({ error: 'Nieprawidłowy e-mail lub hasło.' });
    }

    const user = safeUser(rows[0]);
    req.session.user = user;
    res.json({ user, redirect: '/dashboard.html' });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Nie udało się zalogować.' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: 'Nie udało się wylogować.' });
    res.clearCookie('dominik.sid');
    res.json({ ok: true });
  });
});

app.get('/api/me', (req, res) => {
  res.json({ user: req.session.user ? safeUser(req.session.user) : null });
});

// ---------- ORDERS ----------
app.get('/api/orders', requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT o.id, o.price, o.status, o.notes, o.created_at, o.updated_at,
              s.code AS service_code, s.name AS service_name
       FROM orders o
       JOIN services s ON s.id = o.service_id
       WHERE o.user_id = ?
       ORDER BY o.created_at DESC`,
      [req.session.user.id]
    );
    res.json({ orders: rows });
  } catch (err) {
    console.error('Orders error:', err);
    res.status(500).json({ error: 'Nie udało się pobrać zamówień.' });
  }
});

app.post('/api/create-checkout-session', requireAuth, async (req, res) => {
  let orderId = null;
  try {
    if (!stripe) return res.status(503).json({ error: 'Płatności nie są jeszcze skonfigurowane. Ustaw STRIPE_SECRET_KEY w .env.' });

    const serviceCode = String(req.body.service || '');
    const notes = String(req.body.notes || '').slice(0, 1000);
    if (!SERVICES[serviceCode]) return res.status(400).json({ error: 'Wybrana usługa nie istnieje.' });

    const [serviceRows] = await pool.execute(
      'SELECT id, code, name, price FROM services WHERE code = ? AND active = 1 LIMIT 1',
      [serviceCode]
    );
    if (!serviceRows.length) return res.status(400).json({ error: 'Ta usługa jest obecnie niedostępna.' });

    const service = serviceRows[0];
    const [orderResult] = await pool.execute(
      `INSERT INTO orders (user_id, service_id, price, status, notes)
       VALUES (?, ?, ?, 'pending', ?)`,
      [req.session.user.id, service.id, service.price, notes || null]
    );
    orderId = orderResult.insertId;

    const checkout = await stripe.checkout.sessions.create({
      mode: 'payment',
      locale: 'pl',
      // W tej wersji checkout przyjmuje BLIK. Metoda musi być wcześniej
      // aktywowana w panelu Stripe dla konta produkcyjnego.
      payment_method_types: ['blik'],
      customer_email: req.session.user.email,
      client_reference_id: String(orderId),
      line_items: [{
        quantity: 1,
        price_data: {
          currency: 'pln',
          unit_amount: Math.round(Number(service.price) * 100),
          product_data: {
            name: service.name,
            description: 'Usługa montażu wideo — Dominik Studio'
          }
        }
      }],
      metadata: {
        order_id: String(orderId),
        service: service.code,
        user_id: String(req.session.user.id)
      },
      success_url: `${BASE_URL}/success.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${BASE_URL}/payment.html?service=${encodeURIComponent(service.code)}`
    });

    await pool.execute(
      'UPDATE orders SET stripe_session_id = ? WHERE id = ?',
      [checkout.id, orderId]
    );

    res.json({ url: checkout.url });
  } catch (err) {
    console.error('Checkout error:', err);
    if (orderId) {
      await pool.execute(
        `UPDATE orders SET status = 'cancelled' WHERE id = ? AND status = 'pending'`,
        [orderId]
      ).catch(() => {});
    }
    res.status(500).json({ error: 'Nie udało się utworzyć płatności. Spróbuj ponownie.' });
  }
});

app.get('/api/payment-status', requireAuth, async (req, res) => {
  try {
    const sessionId = String(req.query.session_id || '');
    if (!sessionId || !sessionId.startsWith('cs_')) {
      return res.status(400).json({ error: 'Nieprawidłowa sesja płatności.' });
    }

    const [rows] = await pool.execute(
      `SELECT id, status, price, stripe_session_id
       FROM orders
       WHERE stripe_session_id = ? AND user_id = ?
       LIMIT 1`,
      [sessionId, req.session.user.id]
    );

    if (!rows.length) {
      return res.status(404).json({ error: 'Nie znaleziono zamówienia.' });
    }

    let stripePaymentStatus = null;
    if (stripe) {
      const checkout = await stripe.checkout.sessions.retrieve(sessionId);
      stripePaymentStatus = checkout.payment_status;

      // Awaryjna synchronizacja, gdy webhook jeszcze nie zdążył zaktualizować MySQL.
      if (checkout.payment_status === 'paid' && rows[0].status !== 'paid') {
        await pool.execute(
          `UPDATE orders
           SET status = 'paid', stripe_payment_intent_id = ?, updated_at = CURRENT_TIMESTAMP
           WHERE id = ? AND user_id = ?`,
          [checkout.payment_intent || null, rows[0].id, req.session.user.id]
        );
        rows[0].status = 'paid';
      }
    }

    res.json({
      orderId: rows[0].id,
      status: rows[0].status,
      stripePaymentStatus,
      paid: rows[0].status === 'paid' || stripePaymentStatus === 'paid'
    });
  } catch (err) {
    console.error('Payment status error:', err);
    res.status(500).json({ error: 'Nie udało się sprawdzić statusu płatności.' });
  }
});

app.get('/api/health', async (_req, res) => {
  let mysqlOk = false;
  try {
    await pool.query('SELECT 1');
    mysqlOk = true;
  } catch (_) {}
  res.json({ ok: true, mysql: mysqlOk, stripeConfigured: Boolean(stripe) });
});

app.listen(PORT, async () => {
  try {
    await pool.query('SELECT 1');
    console.log('MySQL: połączono z bazą dominik_studio.');
  } catch (err) {
    console.error('MySQL: brak połączenia:', err.message);
  }
  console.log(`Dominik Studio działa: ${BASE_URL}`);
});
