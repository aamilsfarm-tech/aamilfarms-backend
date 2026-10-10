# Aamil Farms backend

Express + Postgres API for the Aamil Farms pond ledger app (pangasius and IMC culture).

## Environment variables
| Name | Purpose |
| --- | --- |
| `DATABASE_URL` | Postgres connection string |
| `JWT_SECRET` | Long random string used to sign login tokens |
| `OWNER_USERNAME` | Owner login, created on first start if no users exist (3-32 chars: a-z 0-9 . _ -) |
| `OWNER_PASSWORD` | Owner password, 8+ characters |
| `FRONTEND_ORIGIN` | Allowed frontend origin(s), comma separated, e.g. `https://aamilfarms-frontend.onrender.com` |

## Roles
- **owner**: manages ponds and team logins, and can add or delete any record.
- **staff**: adds and deletes water, feed, sampling, mortality, expense and sale entries.

## API
`POST /api/login`, `GET /api/me`, `POST /api/me/password`, `GET/POST /api/users`, `PUT /api/users/:id/password`, `DELETE /api/users/:id`,
`GET /api/sync?since=`, `PUT /api/docs/:col/:id`, `DELETE /api/docs/:col/:id` (col is `ponds` or `entries`), `GET /healthz`.
