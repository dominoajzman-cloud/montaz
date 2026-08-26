```javascript
require('dotenv').config();

const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const Stripe = require('stripe');
const session = require('express-session');
const pg = require('pg');
const connectPgSimple = require('connect-pg-simple');

const { Pool } = pg;

const app = express();

const PORT = Number(process.env.PORT || 3000);

const BASE_URL =
  process.env.BASE_URL ||
  process.env.RENDER_EXTERNAL_URL ||
  `http://localhost:${PORT}`;

// =====================================================
// POSTGRESQL / SUPABASE
// =====================================================

if (!process.env.DATABASE_URL) {
  console.error('BRAK DATABASE_URL!');
  console.error('Ustaw DATABASE_URL w Render -> Environment.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 15000
});

// =====================================================
// STRIPE
// =====================================================

const stripe = process.env.STRIPE_SECRET_KEY
  ? Stripe(process.env.STRIPE_SECRET_KEY)
  : null;

// =====================================================
// USŁUGI
// =====================================================

const SERVICES = {
  short: 'Krótki film',
  long: 'Dłuższy materiał',
  veryLong: 'Bardzo długi materiał',
  short10: '10 × krótki film',
  long10: '10 × dłuższy materiał',
  veryLong10: '10 × bardzo długi materiał'
};

// =====================================================
// STRIPE WEBHOOK
// MUSI BYĆ PRZED express.json()
// =====================================================

app.post(
  '/api/webhook',
  express.raw({ type: 'application/json' }),
  async (req, res) => {
    if (!stripe || !process.env.STRIPE_WEBHOOK_SECRET) {
      return res
        .status(503)
        .send('Webhook nie jest skonfigurowany.');
    }

    let event;

    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        req.headers['stripe-signature'],
        process.env.STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      console.error(
        'Webhook signature error:',
        err.message
      );

      return res
        .status(400)
        .send(`Webhook Error: ${err.message}`);
    }

    try {
      // -------------------------------------------------
      // PŁATNOŚĆ ZAKOŃCZONA
      // -------------------------------------------------

      if (event.type === 'checkout.session.completed') {
        const checkout = event.data.object;

        const orderId = Number(
          checkout.metadata?.order_id
        );

        if (orderId) {
          await pool.query(
            `
            UPDATE orders
            SET
              status = 'paid',
              stripe_payment_intent_id = $1,
              updated_at = CURRENT_TIMESTAMP
            WHERE id = $2
            `,
            [
              checkout.payment_intent || null,
              orderId
            ]
          );

          console.log(
            `Zamówienie #${orderId} oznaczone jako OPŁACONE.`
          );
        }
      }

      // -------------------------------------------------
      // CHECKOUT WYGASŁ
      // -------------------------------------------------

      if (event.type === 'checkout.session.expired') {
        const checkout = event.data.object;

        const orderId = Number(
          checkout.metadata?.order_id
        );

        if (orderId) {
          await pool.query(
            `
            UPDATE orders
            SET
              status = 'cancelled',
              updated_at = CURRENT_TIMESTAMP
            WHERE id = $1
              AND status = 'pending'
            `,
            [orderId]
          );
        }
      }

      return res.json({
        received: true
      });

    } catch (err) {
      console.error(
        'Webhook database error:',
        err
      );

      return res
        .status(500)
        .send('Webhook database error');
    }
  }
);

// =====================================================
// JSON
// =====================================================

app.use(express.json());

// =====================================================
// SESJE
// =====================================================

const PgSession = connectPgSimple(session);

const sessionStore = new PgSession({
  pool: pool,

  tableName: 'session',

  createTableIfMissing: true,

  pruneSessionInterval: 900000
});

app.use(
  session({
    name: 'dominik.sid',

    secret:
      process.env.SESSION_SECRET ||
      'CHANGE_THIS_SESSION_SECRET',

    resave: false,

    saveUninitialized: false,

    store: sessionStore,

    cookie: {
      httpOnly: true,

      sameSite: 'lax',

      secure:
        process.env.NODE_ENV === 'production',

      maxAge:
        1000 *
        60 *
        60 *
        24 *
        7
    }
  })
);

// =====================================================
// PLIKI STATYCZNE
// =====================================================

app.use(
  express.static(path.join(__dirname))
);

// =====================================================
// AUTH HELPERS
// =====================================================

function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({
      error: 'Musisz być zalogowany.'
    });
  }

  next();
}

function safeUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role
  };
}

// =====================================================
// REGISTER
// =====================================================

app.post('/api/register', async (req, res) => {
  try {
    const name = String(
      req.body.name || ''
    ).trim();

    const email = String(
      req.body.email || ''
    )
      .trim()
      .toLowerCase();

    const password = String(
      req.body.password || ''
    );

    // -------------------------------------------------
    // WALIDACJA
    // -------------------------------------------------

    if (name.length < 2) {
      return res.status(400).json({
        error:
          'Podaj poprawne imię lub nazwę.'
      });
    }

    if (
      !/^\S+@\S+\.\S+$/.test(email)
    ) {
      return res.status(400).json({
        error:
          'Podaj poprawny adres e-mail.'
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error:
          'Hasło musi mieć minimum 8 znaków.'
      });
    }

    // -------------------------------------------------
    // SPRAWDZENIE CZY EMAIL ISTNIEJE
    // -------------------------------------------------

    const existingResult =
      await pool.query(
        `
        SELECT id
        FROM users
        WHERE email = $1
        LIMIT 1
        `,
        [email]
      );

    if (existingResult.rows.length) {
      return res.status(409).json({
        error:
          'Konto z tym adresem e-mail już istnieje.'
      });
    }

    // -------------------------------------------------
    // HASH HASŁA
    // -------------------------------------------------

    const passwordHash =
      await bcrypt.hash(
        password,
        12
      );

    // -------------------------------------------------
    // UTWORZENIE UŻYTKOWNIKA
    // -------------------------------------------------

    const result =
      await pool.query(
        `
        INSERT INTO users
          (
            name,
            email,
            password_hash,
            role
          )
        VALUES
          (
            $1,
            $2,
            $3,
            'client'
          )
        RETURNING
          id,
          name,
          email,
          role
        `,
        [
          name,
          email,
          passwordHash
        ]
      );

    const user =
      result.rows[0];

    // -------------------------------------------------
    // SESJA
    // -------------------------------------------------

    req.session.user =
      safeUser(user);

    return res.status(201).json({
      user: safeUser(user),
      redirect: '/dashboard.html'
    });

  } catch (err) {
    console.error(
      'Register error:',
      err
    );

    return res.status(500).json({
      error:
        'Nie udało się utworzyć konta.'
    });
  }
});

// =====================================================
// LOGIN
// =====================================================

app.post('/api/login', async (req, res) => {
  try {
    const email = String(
      req.body.email || ''
    )
      .trim()
      .toLowerCase();

    const password = String(
      req.body.password || ''
    );

    const result =
      await pool.query(
        `
        SELECT
          id,
          name,
          email,
          password_hash,
          role
        FROM users
        WHERE email = $1
        LIMIT 1
        `,
        [email]
      );

    if (!result.rows.length) {
      return res.status(401).json({
        error:
          'Nieprawidłowy e-mail lub hasło.'
      });
    }

    const databaseUser =
      result.rows[0];

    const passwordCorrect =
      await bcrypt.compare(
        password,
        databaseUser.password_hash
      );

    if (!passwordCorrect) {
      return res.status(401).json({
        error:
          'Nieprawidłowy e-mail lub hasło.'
      });
    }

    const user =
      safeUser(databaseUser);

    req.session.user =
      user;

    return res.json({
      user,
      redirect:
        '/dashboard.html'
    });

  } catch (err) {
    console.error(
      'Login error:',
      err
    );

    return res.status(500).json({
      error:
        'Nie udało się zalogować.'
    });
  }
});

// =====================================================
// LOGOUT
// =====================================================

app.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error(
        'Logout error:',
        err
      );

      return res.status(500).json({
        error:
          'Nie udało się wylogować.'
      });
    }

    res.clearCookie(
      'dominik.sid'
    );

    return res.json({
      ok: true
    });
  });
});

// =====================================================
// CURRENT USER
// =====================================================

app.get('/api/me', (req, res) => {
  return res.json({
    user:
      req.session.user
        ? safeUser(
            req.session.user
          )
        : null
  });
});

// =====================================================
// ORDERS — LISTA
// =====================================================

app.get(
  '/api/orders',
  requireAuth,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT
            o.id,
            o.price,
            o.status,
            o.notes,
            o.created_at,
            o.updated_at,
            s.code AS service_code,
            s.name AS service_name
          FROM orders o
          JOIN services s
            ON s.id = o.service_id
          WHERE o.user_id = $1
          ORDER BY
            o.created_at DESC
          `,
          [
            req.session.user.id
          ]
        );

      return res.json({
        orders:
          result.rows
      });

    } catch (err) {
      console.error(
        'Orders error:',
        err
      );

      return res.status(500).json({
        error:
          'Nie udało się pobrać zamówień.'
      });
    }
  }
);

// =====================================================
// CREATE STRIPE CHECKOUT
// =====================================================

app.post(
  '/api/create-checkout-session',
  requireAuth,
  async (req, res) => {

    let orderId = null;

    try {

      if (!stripe) {
        return res.status(503).json({
          error:
            'Płatności nie są jeszcze skonfigurowane.'
        });
      }

      const serviceCode =
        String(
          req.body.service || ''
        );

      const notes =
        String(
          req.body.notes || ''
        ).slice(0, 1000);

      if (
        !SERVICES[serviceCode]
      ) {
        return res.status(400).json({
          error:
            'Wybrana usługa nie istnieje.'
        });
      }

      // -------------------------------------------------
      // POBIERAMY USŁUGĘ
      // -------------------------------------------------

      const serviceResult =
        await pool.query(
          `
          SELECT
            id,
            code,
            name,
            price
          FROM services
          WHERE code = $1
            AND active = TRUE
          LIMIT 1
          `,
          [serviceCode]
        );

      if (
        !serviceResult.rows.length
      ) {
        return res.status(400).json({
          error:
            'Ta usługa jest obecnie niedostępna.'
        });
      }

      const service =
        serviceResult.rows[0];

      // -------------------------------------------------
      // TWORZYMY ZAMÓWIENIE
      // -------------------------------------------------

      const orderResult =
        await pool.query(
          `
          INSERT INTO orders
            (
              user_id,
              service_id,
              price,
              status,
              notes
            )
          VALUES
            (
              $1,
              $2,
              $3,
              'pending',
              $4
            )
          RETURNING id
          `,
          [
            req.session.user.id,
            service.id,
            service.price,
            notes || null
          ]
        );

      orderId =
        orderResult.rows[0].id;

      // -------------------------------------------------
      // STRIPE
      // -------------------------------------------------

      const checkout =
        await stripe.checkout.sessions.create({
          mode: 'payment',

          locale: 'pl',

          payment_method_types: [
            'blik'
          ],

          customer_email:
            req.session.user.email,

          client_reference_id:
            String(orderId),

          line_items: [
            {
              quantity: 1,

              price_data: {
                currency: 'pln',

                unit_amount:
                  Math.round(
                    Number(
                      service.price
                    ) * 100
                  ),

                product_data: {
                  name:
                    service.name,

                  description:
                    'Usługa montażu wideo — Dominik Studio'
                }
              }
            }
          ],

          metadata: {
            order_id:
              String(orderId),

            service:
              service.code,

            user_id:
              String(
                req.session.user.id
              )
          },

          success_url:
            `${BASE_URL}/success.html?session_id={CHECKOUT_SESSION_ID}`,

          cancel_url:
            `${BASE_URL}/payment.html?service=${encodeURIComponent(
              service.code
            )}`
        });

      // -------------------------------------------------
      // ZAPISUJEMY SESJĘ STRIPE
      // -------------------------------------------------

      await pool.query(
        `
        UPDATE orders
        SET
          stripe_session_id = $1,
          updated_at = CURRENT_TIMESTAMP
        WHERE id = $2
        `,
        [
          checkout.id,
          orderId
        ]
      );

      return res.json({
        url:
          checkout.url
      });

    } catch (err) {

      console.error(
        'Checkout error:',
        err
      );

      if (orderId) {
        await pool.query(
          `
          UPDATE orders
          SET
            status = 'cancelled',
            updated_at = CURRENT_TIMESTAMP
          WHERE id = $1
            AND status = 'pending'
          `,
          [orderId]
        ).catch(() => {});
      }

      return res.status(500).json({
        error:
          'Nie udało się utworzyć płatności. Spróbuj ponownie.'
      });
    }
  }
);

// =====================================================
// PAYMENT STATUS
// =====================================================

app.get(
  '/api/payment-status',
  requireAuth,
  async (req, res) => {

    try {

      const sessionId =
        String(
          req.query.session_id || ''
        );

      if (
        !sessionId ||
        !sessionId.startsWith('cs_')
      ) {
        return res.status(400).json({
          error:
            'Nieprawidłowa sesja płatności.'
        });
      }

      const result =
        await pool.query(
          `
          SELECT
            id,
            status,
            price,
            stripe_session_id
          FROM orders
          WHERE stripe_session_id = $1
            AND user_id = $2
          LIMIT 1
          `,
          [
            sessionId,
            req.session.user.id
          ]
        );

      if (!result.rows.length) {
        return res.status(404).json({
          error:
            'Nie znaleziono zamówienia.'
        });
      }

      const order =
        result.rows[0];

      let stripePaymentStatus =
        null;

      if (stripe) {

        const checkout =
          await stripe.checkout.sessions.retrieve(
            sessionId
          );

        stripePaymentStatus =
          checkout.payment_status;

        // -------------------------------------------------
        // AWARYJNA SYNCHRONIZACJA
        // -------------------------------------------------

        if (
          checkout.payment_status ===
            'paid' &&
          order.status !== 'paid'
        ) {

          await pool.query(
            `
            UPDATE orders
            SET
              status = 'paid',
              stripe_payment_intent_id = $1,
              updated_at = CURRENT_TIMESTAMP
            WHERE id = $2
              AND user_id = $3
            `,
            [
              checkout.payment_intent ||
                null,

              order.id,

              req.session.user.id
            ]
          );

          order.status =
            'paid';
        }
      }

      return res.json({
        orderId:
          order.id,

        status:
          order.status,

        stripePaymentStatus,

        paid:
          order.status ===
            'paid' ||
          stripePaymentStatus ===
            'paid'
      });

    } catch (err) {

      console.error(
        'Payment status error:',
        err
      );

      return res.status(500).json({
        error:
          'Nie udało się sprawdzić statusu płatności.'
      });
    }
  }
);

// =====================================================
// MESSAGES
// =====================================================

app.get(
  '/api/orders/:orderId/messages',
  requireAuth,
  async (req, res) => {

    try {

      const orderId =
        Number(
          req.params.orderId
        );

      if (
        !Number.isInteger(
          orderId
        )
      ) {
        return res.status(400).json({
          error:
            'Nieprawidłowe ID zamówienia.'
        });
      }

      // Sprawdzamy czy zamówienie należy
      // do aktualnego użytkownika.

      const orderResult =
        await pool.query(
          `
          SELECT id
          FROM orders
          WHERE id = $1
            AND user_id = $2
          LIMIT 1
          `,
          [
            orderId,
            req.session.user.id
          ]
        );

      if (
        !orderResult.rows.length
      ) {
        return res.status(404).json({
          error:
            'Nie znaleziono zamówienia.'
        });
      }

      const result =
        await pool.query(
          `
          SELECT
            m.id,
            m.order_id,
            m.user_id,
            m.message,
            m.created_at,
            u.name AS user_name,
            u.role AS user_role
          FROM messages m
          JOIN users u
            ON u.id = m.user_id
          WHERE m.order_id = $1
          ORDER BY
            m.created_at ASC
          `,
          [orderId]
        );

      return res.json({
        messages:
          result.rows
      });

    } catch (err) {

      console.error(
        'Messages error:',
        err
      );

      return res.status(500).json({
        error:
          'Nie udało się pobrać wiadomości.'
      });
    }
  }
);

// =====================================================
// SEND MESSAGE
// =====================================================

app.post(
  '/api/orders/:orderId/messages',
  requireAuth,
  async (req, res) => {

    try {

      const orderId =
        Number(
          req.params.orderId
        );

      const message =
        String(
          req.body.message || ''
        ).trim();

      if (
        !Number.isInteger(
          orderId
        )
      ) {
        return res.status(400).json({
          error:
            'Nieprawidłowe ID zamówienia.'
        });
      }

      if (!message) {
        return res.status(400).json({
          error:
            'Wiadomość nie może być pusta.'
        });
      }

      if (message.length > 5000) {
        return res.status(400).json({
          error:
            'Wiadomość jest za długa.'
        });
      }

      const orderResult =
        await pool.query(
          `
          SELECT id
          FROM orders
          WHERE id = $1
            AND user_id = $2
          LIMIT 1
          `,
          [
            orderId,
            req.session.user.id
          ]
        );

      if (
        !orderResult.rows.length
      ) {
        return res.status(404).json({
          error:
            'Nie znaleziono zamówienia.'
        });
      }

      const result =
        await pool.query(
          `
          INSERT INTO messages
            (
              order_id,
              user_id,
              message
            )
          VALUES
            (
              $1,
              $2,
              $3
            )
          RETURNING
            id,
            order_id,
            user_id,
            message,
            created_at
          `,
          [
            orderId,
            req.session.user.id,
            message
          ]
        );

      return res.status(201).json({
        message:
          result.rows[0]
      });

    } catch (err) {

      console.error(
        'Send message error:',
        err
      );

      return res.status(500).json({
        error:
          'Nie udało się wysłać wiadomości.'
      });
    }
  }
);

// =====================================================
// HEALTH CHECK
// =====================================================

app.get(
  '/api/health',
  async (_req, res) => {

    let databaseOk =
      false;

    let databaseError =
      null;

    try {

      await pool.query(
        'SELECT 1'
      );

      databaseOk =
        true;

    } catch (err) {

      databaseError =
        err.message;

      console.error(
        'Database health error:',
        err.message
      );
    }

    return res.json({
      ok: true,

      database:
        databaseOk,

      stripeConfigured:
        Boolean(stripe),

      baseUrl:
        BASE_URL,

      databaseError
    });
  }
);

// =====================================================
// START
// =====================================================

app.listen(
  PORT,
  async () => {

    console.log(
      '=============================================='
    );

    console.log(
      'Dominik Studio startuje...'
    );

    console.log(
      `PORT: ${PORT}`
    );

    console.log(
      `BASE_URL: ${BASE_URL}`
    );

    console.log(
      `Stripe: ${
        stripe
          ? 'SKONFIGUROWANY'
          : 'BRAK'
      }`
    );

    console.log(
      'Database: Supabase PostgreSQL'
    );

    console.log(
      '=============================================='
    );

    try {

      await pool.query(
        'SELECT 1'
      );

      console.log(
        'PostgreSQL: POŁĄCZONO z Supabase.'
      );

    } catch (err) {

      console.error(
        'PostgreSQL: BRAK POŁĄCZENIA!'
      );

      console.error(
        err.message
      );
    }

    console.log(
      `Dominik Studio działa: ${BASE_URL}`
    );
  }
);
```


