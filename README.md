# WEAR ME: server files (back end)

This is the storage and admin server for the website in `1-site-files`. It keeps the shop's data
(products, prices, settings, orders, sewing requests, accounts of money in and out), the uploaded pictures and videos,
and the owner's login. It needs **only Node.js 18 or newer**. There is nothing to `npm install`.

| File | What it is |
|---|---|
| `server.js` | The whole server. |
| `package.json` | Lets you start it with `npm start` (no packages inside). |
| `.env.example` | All settings. Copy it to `.env` and edit. |
| `.gitignore` | Keeps `.env`, `data/` and `uploads/` out of git. |
| `README.md` | This file. |

Created automatically when it runs: `data/` (the database and admin account) and `uploads/` (pictures and videos).

## Start it

```
node server.js
```

It listens on port 4000 (`PORT` in `.env`). Check `http://localhost:4000/api/health`, which should show `{"ok":true}`.
Then follow `1-site-files/README.md` to point the website at it.

## Settings (`.env`)

| Setting | Meaning |
|---|---|
| `PORT` | Port to listen on (default 4000). |
| `ALLOWED_ORIGINS` | Website addresses allowed to use the server, comma separated. Use your real domain(s) when live, not `*`. |
| `ADMIN_EMAIL` | If set, only this email can create the admin account. **Set this before you put the server online**, otherwise the first person to find `admin.html` could create it. |
| `SESSION_HOURS` | How long an admin login lasts (default 12). |
| `MAX_UPLOAD_MB` | Biggest upload (default 25). Banner videos are the big ones. |
| `TRUST_PROXY` | Set to `1` behind a proxy or most hosts, so login limits count each visitor separately. |
| `DATA_DIR`, `UPLOAD_DIR` | Where data and files are kept. Put them on storage that survives restarts. |
| `SITE_DIR` | Optional. A path such as `../1-site-files` makes this server also serve the website, so one host does everything (then set `apiBase` to `""`). |

## Putting it online

Any host that runs Node works (a small VPS, Render, Railway, Fly.io, cPanel "Setup Node.js App").
Make sure the host keeps the `data/` and `uploads/` folders between restarts (a persistent disk or volume). Serve it over HTTPS.
Back up `data/` and `uploads/` regularly: copying those two folders is a full backup.

## How the data is stored

Everything is in `data/db.json` (shop data) and `data/admin.json` (the admin account, with the password stored as a salted scrypt hash,
never as plain text). Uploaded files are in `uploads/`. This is simple and fine for a small shop with hundreds of orders.
If the shop grows a lot, replace the small storage section at the top of `server.js` with a real database (SQLite, Postgres or MongoDB).
The website will not need to change because it only talks to the API below.

## Admin account

- One account only. The first visit to `admin.html` creates it (email + password), then the owner adds name, date of birth and so on.
- Passwords are checked on the server, with a limit of 8 wrong tries per 15 minutes per visitor.
- **Forgot the password?** There is no email reset yet. Stop the server, delete `data/admin.json`, start it again, and create the account again.
  Your shop data is untouched.
- Share the login with anyone you trust. Logging in on a second device works at the same time.

## What visitors can and cannot do

| Who | Can | Cannot |
|---|---|---|
| Anyone | Read products and settings. Create an order or a sewing request (a new one only). Upload an image up to 10 MB. Read orders for an email address they give. Report a problem on a paid order, once. | Read other collections. Change or delete anything. Mark an order Paid, Delivered or Refunded. Upload video. |
| Admin (logged in) | Everything. | |

The server also resets the safe fields on new orders (status New, not Paid) so a customer cannot mark their own order Paid.

## API (for reference)

All paths are on the server address. `Authorization: Bearer <token>` is sent for admin calls.

| Call | Use |
|---|---|
| `GET /api/health` | Is the server up. |
| `GET /api/doc?path=products/1` | Read one record. |
| `GET /api/col?name=products` | Read a list (`orders` needs `&where=email,==,name@mail.com` unless admin). |
| `PUT /api/doc?path=...` | Create or replace a record. |
| `PATCH /api/doc?path=...` | Change some fields of a record. |
| `DELETE /api/doc?path=...` | Delete a record (admin). |
| `POST /api/upload` | Upload a file (body is the file, `Content-Type` is its type). Returns `{id, url}`. |
| `GET /blob/<id>` | A stored picture or video. |
| `GET /api/admin/status`, `POST /api/admin/create`, `/login`, `/logout`, `PUT /api/admin/profile`, `POST /api/admin/password` | The admin account. |

Collections: `products`, `settings` (`site`, `banners`), `orders`, `styling` (sewing requests), `ledger` (the owner's other income and expenses).

## Before going live: checklist

1. Set `ADMIN_EMAIL`, `ALLOWED_ORIGINS` and `TRUST_PROXY=1` in `.env`. Serve over HTTPS.
2. Create the admin account straight away, and replace the sample bank details (Finance > Company account).
3. Fill in contact numbers, socials, legal pages and size guides in the dashboard.
4. Real customer log-in (so order history is private and works on any device), Google and Apple sign-in, and real card payment are **not** part of this version. They are the next pieces of work.
5. Set up automatic backups of `data/` and `uploads/`.
