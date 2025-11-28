
# 🛡️ CyberX Encryptor: Multi-Cipher Simulation Stack

CyberX Encryptor is a full-stack, educational application designed to encrypt user messages using a **randomized, layered sequence** of both classical and modern ciphers. It uses **Flask** for the backend, **PostgreSQL** for secure session storage, and is containerized using **Docker Compose** for reliable deployment.

A core feature is the **Attack Simulation** route (`/simulate`), which analyzes the generated ciphertext for common weaknesses using techniques like **Kasiski Examination** (for Vigenère), Brute Force (for Caesar/Rail-Fence), and **entropy analysis** to calculate a **Security Strength Score**.

---

## 🚀 Quick Start (Docker Compose)

The easiest way to run the entire application, including the database, is using Docker Compose.

### Prerequisites

* Docker and Docker Compose installed.
* Your application files (`CyberX_2.py`, `docker-compose.yml`, `entrypoint.sh`, etc.) must be in the same root directory.

### 1. Build and Run the Stack

Run the following command from your project root directory. The `--build` flag ensures your latest Python files and the crucial `entrypoint.sh` script are included.

```bash
docker compose up --build
````

This process will:

1.  Start the **`cyberx-postgres`** database container.
2.  Start the **`cyberx-app`** container.
3.  Execute **`entrypoint.sh`** to **wait for the database** and automatically **create the necessary tables** (`cipher_session`) before starting the web server.
4.  Start the Gunicorn web server.

### 2\. Access the Application

The Flask application is exposed on your host machine's port **5000**.

  * **Open your browser:** `http://localhost:5000`

### 3\. Test the API Endpoints

The application routes handle the core logic:

| Endpoint | Method | Purpose | Example Command |
| :--- | :--- | :--- | :--- |
| `/encrypt` | `POST` | Encrypts a message with a random cipher sequence and stores the session. | `curl -X POST http://localhost:5000/encrypt -d "message=Your secret message"` |
| `/decrypt` | `POST` | Retrieves the ciphertext and keys by `session_id` to decrypt the message. | `curl -X POST http://localhost:5000/decrypt -d "session_id=8CHARID"` |
| `/simulate`| `POST` | Runs a series of classical attacks and security analysis on the stored ciphertext. | `curl -X POST http://localhost:5000/simulate -d "session_id=8CHARID"` |

-----

## 🏗️ Project Architecture Overview

The application is structured as a two-service stack:

### 1\. `cyberx-app` (Web Service)

  * **Runtime:** Python 3.11-slim base image.
  * **Dependencies:** `Flask`, `Flask-SQLAlchemy`, `gunicorn`, `psycopg2-binary`, `pycryptodomex`, `numpy`.
  * **Startup Sequence (Entrypoint):**
    ```bash
    # 1. Database Check and Table Creation
    python -c "from CyberX_2 import db, app; app.app_context().push(); db.create_all()"
    # 2. Start Web Server
    exec gunicorn --bind 0.0.0.0:8080 CyberX_2:app
    ```
  * **Networking:** Listens on container port `8080`, mapped to host port `5000`.

### 2\. `cyberx-postgres` (Database Service)

  * **Image:** `postgres:latest`.
  * **Database Name:** `cyberx_db`.
  * **Persistence:** Uses a named volume (`postgres_data`) for persistent data storage.
  * **Connection URL (in app):** `postgresql://postgres:password123@db:5432/cyberx_db`. The service name `db` acts as the network hostname.

-----

## 🔐 Cipher and Key Management

The application's core logic is layered encryption, where the sequence of ciphers is randomized.

The **`CipherSession`** model stores the necessary decryption information:

| Column | Type | Purpose |
| :--- | :--- | :--- |
| `id` | `VARCHAR(8)` | The unique Session ID (Primary Key). |
| `ciphertext` | `Text` | The final, layered encrypted message. |
| `infos_json` | `Text` | A JSON-serialized list containing the cipher sequence, keys (e.g., AES bytes, RSA private key object), and parameters required for decryption. |

## ⚙️ Development and Customization

If you need to make changes to the code or inspect the database state:

1.  **Stop the running containers:**
    ```bash
    docker compose down
    ```
2.  **Make changes** to any source file (`CyberX_2.py`, `requirements.txt`, etc.).
3.  **Restart with rebuild** to apply the changes:
    ```bash
    docker compose up --build
    ```
4.  **Database Inspection:** To directly view the stored data (ciphertext, keys, etc.) from a successful encryption:
    ```bash
    docker exec -it cyberx-postgres psql -U postgres -d cyberx_db
    # Then run this SQL command:
    SELECT id, ciphertext, infos_json FROM cipher_session;
    ```

<!-- end list -->

```
```