# Manufacturing Production Planning System (full stack)

Flask REST API + SQLite database + browser front end, all in this folder.

## Run
    pip install -r requirements.txt
    python app.py
Open http://127.0.0.1:5000. First run creates `planning.db` (sample data) and `.secret_key`.
Open the folder in VS Code (File > Open Folder) and run the commands in its terminal.

## Logins (change them in Account > Change password)
- planner / plan123: full access, user management, audit log
- supervisor / sup123: dashboard, schedule (view), materials (view), progress

## Assistant and help
- Click "Ask assistant" (or press ?) for help with any feature. It also knows what is delayed, short or idle right now.
- Works offline with a built-in guide. For answers from Claude, set ANTHROPIC_API_KEY (and optionally ANTHROPIC_MODEL) before `python app.py`; the key stays on the server.
- Every page starts with a short "What is this page?" box that you can collapse.

## Tests
    pip install pytest
    python -m pytest -q

## Files
- app.py: schema, auto-scheduling, REST API, security
- static/index.html: the website (calls the API)
- test_api.py: automated tests for login, roles, CSRF, validation, lockout

## Security built in
- Passwords stored hashed; 8+ character rule with letter and digit for new passwords
- Server-side sessions: HttpOnly, SameSite=Lax cookie, 2-hour expiry (set HTTPS=1 behind HTTPS to add Secure)
- CSRF token required on every POST, PUT and DELETE
- Login lockout: 5 failed attempts per user and IP locks sign-in for 5 minutes
- Role checks on every API route; all SQL is parameterized; inputs validated; request size capped at 64 KB
- Security headers (CSP, frame blocking, nosniff, no-referrer); audit log of every change
- Secret key generated on first run (or set SECRET_KEY); debug mode off unless DEBUG=1

## API
Signed-in users can list every route at /api/docs. Main ones: GET /api/state; POST /api/orders;
PUT, DELETE /api/orders/<id>; POST /api/progress, /api/tick, /api/password, /api/users;
POST /api/machines/<id>/toggle, /api/schedule/<id>/machine, /api/materials/<id>/restock; GET /api/export/<orders|schedule>.csv

## Before real use
Run behind HTTPS (set HTTPS=1), use a production server such as gunicorn or waitress instead of `python app.py`,
and replace the demo passwords.
