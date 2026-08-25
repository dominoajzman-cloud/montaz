# Dominik Studio — montaż wideo + konta + Stripe

Projekt zawiera stronę, rejestrację/logowanie, sesje zapisane w MySQL, panel klienta oraz checkout Stripe.

## 1. Baza danych

Utwórz bazę `dominik_studio` i tabele z przygotowanego wcześniej skryptu SQL. Tabela `sessions` zostanie utworzona automatycznie przez `express-mysql-session`.

## 2. Konfiguracja

Skopiuj `.env.example` jako `.env` i wpisz prawdziwe dane MySQL oraz klucze Stripe. Nie publikuj pliku `.env`.

Przykład lokalnie:

```env
PORT=3000
BASE_URL=http://localhost:3000
SESSION_SECRET=dlugi-losowy-sekret
NODE_ENV=development
MYSQL_HOST=localhost
MYSQL_PORT=3306
MYSQL_USER=root
MYSQL_PASSWORD=twoje_haslo
MYSQL_DATABASE=dominik_studio
STRIPE_SECRET_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
```

## 3. Instalacja

```bash
npm install
npm start
```

Wejdź na `http://localhost:3000`.

## 4. System kont

- `register.html` — rejestracja
- `login.html` — logowanie
- `dashboard.html` — konto i zamówienia
- sesje użytkowników są przechowywane w MySQL
- hasła są hashowane przez bcrypt

## 5. Płatności

Użytkownik musi być zalogowany, aby zamówić usługę. Backend pobiera cenę z tabeli `services`, tworzy zamówienie `pending`, tworzy Stripe Checkout i zapisuje jego ID. Webhook Stripe zmienia zamówienie na `paid` dopiero po potwierdzeniu płatności.

## 6. Ważne przed publikacją

Przed produkcją ustaw HTTPS, `NODE_ENV=production`, bezpieczny `SESSION_SECRET`, produkcyjne klucze Stripe i webhook Stripe. Dodaj też politykę prywatności, regulamin i zasady realizacji usług.
