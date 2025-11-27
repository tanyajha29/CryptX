# CryptX (CyberX-2)

Minimal README to build and run the CryptX Flask app.

Files:
- [CyberX-2.py](CyberX-2.py) — main app; exposes Flask [`app`](CyberX-2.py) and DB model [`CipherSession`](CyberX-2.py).
- [docker-compose.yml](docker-compose.yml) — local Docker stack (Postgres + app).
- [dockerfile](dockerfile) — image build for the app.
- [requirements.txt](requirements.txt) — Python deps.
- [templates/index.html](templates/index.html) — UI.
- [static/style.css](static/style.css) — styling.

Key runtime symbols:
- DB startup wait: [`wait_for_db`](CyberX-2.py)
- DB init: [`db.create_all`](CyberX-2.py)
- Encryption/decryption: [`random_multi_encrypt`](CyberX-2.py), [`random_multi_decrypt`](CyberX-2.py)

Quick start — Docker (recommended)
1. From project root run:
   - docker-compose up --build
   - or docker-compose up --build -d  (run detached)
2. Wait for services to be healthy. The frontend is mapped to host port 5000 (compose maps `5000:8080`).
3. Open http://localhost:5000

Notes:
- The compose file sets DATABASE_URL to: `postgresql://postgres:password123@db:5432/cyberx_db` (service hostname is `db`). See [docker-compose.yml](docker-compose.yml).
- The app contains a DB retry helper [`wait_for_db`](CyberX-2.py) to handle container race conditions.

Quick start — Local (no Docker)
1. Create & activate virtualenv:
   - python -m venv venv
   - venv\Scripts\activate (Windows) or source venv/bin/activate (macOS/Linux)
2. Fix `requirements.txt` if it contains comment lines starting with `//` (remove `//` lines).
3. Install:
   - pip install -r requirements.txt
4. Run:
   - python CyberX-2.py
5. Open http://127.0.0.1:5000

Troubleshooting
- "password authentication failed" when running locally: ensure Postgres container uses same password as DATABASE_URL. You can inspect container env or recreate with `POSTGRES_PASSWORD=password123`. See [docker-compose.yml](docker-compose.yml).
- If app fails because DB not ready, [`wait_for_db`](CyberX-2.py) tries reconnects. Logs printed in container will show retries.

Useful commands
- docker-compose logs -f
- docker-compose up --build --force-recreate
- docker-compose down -v  (remove volumes)

License / Security
- This project is educational. Do not use for production secrets. Keys and crypto modes here are for demo only. See [`CyberX-2.py`](CyberX-2.py) for implementation details.

If you want, I can:
- add a README file to the repo,
- update `dockerfile` CMD to a shell form,
- or create a small healthcheck for the DB service in `docker-compose.yml`.
