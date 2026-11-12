# Bee Sweet server

Node + Express + PostgreSQL API. Tables are created automatically on first start.

## Deploy on Railway
1. New project, then Add PostgreSQL.
2. New service from this folder (GitHub repo of this folder, or `railway up`).
3. Add the variables listed in env-example.txt to this service.
4. Settings, Networking, Generate Domain. Put that URL in the site's config.js (API_BASE).
5. Paystack dashboard, Settings, API Keys and Webhooks: set the webhook URL to
   https://YOUR-SERVER-DOMAIN/api/paystack/webhook
6. Open the admin page, log in with ADMIN_EMAIL and ADMIN_PASSWORD, add products.

Changing ADMIN_PASSWORD and redeploying resets the admin password.
Uploaded images, videos and receipts are stored in the database.
