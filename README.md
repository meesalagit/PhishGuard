# Sentinel QA Backend: Login & role-based access API

FastAPI backend for Sentinel QA login. It implements the API contract the frontend expects (see `frontend/README.md`) on top of the role-based access database in `scripts/db/role_access/`.

```
Next.js  POST /api/auth/login  (email + password)
   │
   └──▶ FastAPI  POST /api/auth/login  (OAuth 2 password form)
          └──▶ PostgreSQL  auth_login(email, password)   bcrypt check inside the DB
          ◀── JWT (30 min) + { id, email, full_name, role }

Every later call: "Authorization: Bearer <JWT>"
   FastAPI checks the JWT, then runs the request in one transaction with
   app_set_user(<user id>) so the database's Row-Level Security applies.
```

## Folder structure

```
backend/
├── app/
│   ├── main.py          # FastAPI app, DB pool open/close, /api/health
│   ├── config.py        # Settings from .env (refuses a weak JWT_SECRET)
│   ├── db.py            # Connection pool + transaction(user_id) helper
│   ├── security.py      # Create and verify JWTs
│   ├── deps.py          # Guards: get_current_user (401), require_permission (403)
│   ├── rate_limit.py    # Lockout after too many failed logins (429)
│   └── routers/
│       ├── auth.py      # POST /api/auth/login, GET /api/auth/me
│       └── admin.py     # GET /api/admin/users (Admin only, example)
├── tests/
│   └── test_auth.py     # 19 pytest tests against the dev database
├── .env.example         # Settings template (copy to .env)
├── pytest.ini
└── requirements.txt
```

## Run it locally

1. **Database.** Start Postgres and run the role-access scripts, including the dev seed (`004_seed_dev_users.sql`). See [docs/00_postgres_setup.md](../docs/00_postgres_setup.md) and [docs/01_role_based_access.md](../docs/01_role_based_access.md).

2. **Python environment** (Python 3.11+):

   ```bash
   cd backend
   python3 -m venv .venv
   source .venv/bin/activate          # Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Settings.** Copy the template and set a real secret:

   ```bash
   cp .env.example .env               # Windows: copy .env.example .env
   python3 -c "import secrets; print(secrets.token_urlsafe(48))"
   ```

   Put the printed value in `JWT_SECRET` in `.env`. The app refuses to start with `change-me` or anything shorter than 32 characters. `.env` is git-ignored.

4. **Start the API:**

   ```bash
   uvicorn app.main:app --reload --port 8000
   ```

   Check http://localhost:8000/api/health → `{"status":"ok","database":"connected","roles":5}`.
   Interactive API docs: http://localhost:8000/docs

5. **Frontend.** In another terminal, follow `frontend/README.md` (`npm install`, `cp .env.example .env.local`, `npm run dev`) and open http://localhost:3000. The demo-accounts panel signs in as each dev user.

### Settings (`.env`)

| Variable | Purpose | Default |
|---|---|---|
| `DATABASE_URL` | Postgres connection as the app user (`APP_DB_USER` from `.env.dev`) | required |
| `JWT_SECRET` | Secret used to sign tokens. At least 32 random characters. | required |
| `JWT_EXPIRES_MINUTES` | Token lifetime | `30` |
| `LOGIN_MAX_FAILURES` | Failed logins before lockout | `5` |
| `LOGIN_LOCKOUT_MINUTES` | Lockout length | `10` |

The backend must connect as the app user (`qa_app_user_dev`), never as `postgres`, so Row-Level Security applies.

### Port 5432 already in use (macOS)

If Postgres is also installed directly on your Mac, it answers on `localhost:5432` before Docker does, and the API fails with `role "qa_app_user_dev" does not exist`. Check with `lsof -nP -iTCP:5432 -sTCP:LISTEN`. Fix: set `POSTGRES_PORT=5435` in the repo's `.env.dev`, run `docker compose --env-file .env.dev up -d`, and use port `5435` in `DATABASE_URL`.

## API

| Endpoint | Request | Response |
|---|---|---|
| `POST /api/auth/login` | form: `username` (email), `password` | `200 { access_token, token_type: "bearer", expires_in, user: { id, email, full_name, role } }`; `401` wrong email or password (same message for both); `422` missing field; `429` too many failed attempts, with `Retry-After` |
| `GET /api/auth/me` | `Authorization: Bearer <JWT>` | `200 { id, email, full_name, role }` (role read fresh from the DB); `401` missing, invalid, expired or forged token, or disabled user |
| `GET /api/admin/users` | `Authorization: Bearer <JWT>` | `200` list of users and roles for Admin; `403` for every other role |
| `GET /api/health` | | `200 { status, database, roles }` |

JWT claims: `sub` (user id), `email`, `name`, `role`, `iat`, `exp`. Signed with HS256.

### Protecting a new endpoint

```python
from typing import Annotated
from fastapi import Depends
from app.db import transaction
from app.deps import CurrentUser, require_permission

@router.get("/projects")
def list_projects(user: CurrentUser):                     # any logged-in user, else 401
    with transaction(user["id"]) as conn:                  # RLS: only the user's projects
        return conn.execute("SELECT id::text, name FROM projects").fetchall()

@router.post("/projects")
def create_project(user: Annotated[dict, Depends(require_permission("project.manage"))]):  # else 403
    ...
```

Permission keys come from `scripts/db/role_access/003_seed_roles_permissions.sql`.

## Security

| Requirement | How it's done |
|---|---|
| Standard, open-source auth | OAuth 2 password flow (`OAuth2PasswordRequestForm`) and JWT (PyJWT) |
| Passwords stored securely | bcrypt hashes in Postgres. The password is checked inside the DB by `auth_login()`, and the app user can't read the hash column. |
| Encrypted in transit | Served over HTTPS in deployment. The frontend keeps the JWT in an httpOnly, Secure cookie. Tokens are sent with `Cache-Control: no-store`. |
| Token safety | Signed with a secret only the backend has (`.env`, git-ignored); 30-minute expiry; only HS256 accepted; expired or forged tokens get 401 |
| Fresh role checks | `/me` and every guard read the role from the DB, so a disabled user or changed role takes effect immediately |
| Database-level access | Each request runs in one transaction with `app_set_user()` (like `SET LOCAL`), so RLS applies and the user is cleared when the transaction ends |
| Brute force | Email locked for 10 minutes after 5 failed logins (429 + `Retry-After`) |
| No account enumeration | Same 401 message for a wrong email, wrong password or disabled account |

The lockout counts are kept in memory, which is fine for one backend server. If the API runs on several servers, move them to a shared store such as Redis.

## Tests

With the database running and seeded:

```bash
cd backend
source .venv/bin/activate
pytest -v
```

19 tests: health, login for all 5 roles, token claims, case-insensitive email, identical 401 for wrong password and unknown email, `/me` with missing, fake, expired and forged tokens, 403 for every non-admin role, lockout, and lockout reset after a successful login.

## Planned follow-ups

- **CDF SSO:** add a second login route; the guards in `deps.py` stay the same.
- **Admin user management:** add, edit and assign roles (endpoints under `/api/admin`).
- **Dev passwords:** move dev users and their passwords out of the repo (admin-only setup), as discussed for the DB scripts.
