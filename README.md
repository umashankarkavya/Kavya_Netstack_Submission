# Nestack Secure Records API

## Overview
A Flask REST API that provides user registration, authentication, and secure record management using SQLite.

## Features
- User registration with bcrypt password hashing.
- Login using bearer tokens and server-side sessions.
- Session expiration.
- Record creation and retrieval.
- Users can access only their own records; administrators can access records belonging to other users.
- Login abuse protection with temporary account lockout after repeated failed attempts.
- Input validation and parameterized SQL queries.
- Automated security tests using pytest.

## Requirements
- Python 3
- Flask
- bcrypt
- pytest

## Setup on Windows
1. Create and activate a virtual environment.
2. Install dependencies:
   `python -m pip install Flask bcrypt pytest`
3. Start the API:
   `python app.py`

The API runs at `http://127.0.0.1:5000`.

## API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/register` | Register a user |
| POST | `/login` | Authenticate and receive a bearer token |
| POST | `/records` | Create a record (authentication required) |
| GET | `/records` | List the authenticated user's records |
| GET | `/records/<record_id>` | Retrieve a record subject to role and ownership checks |

## Authentication
For protected endpoints, send the token returned by `/login` in the HTTP Authorization header:

`Authorization: Bearer YOUR_ACCESS_TOKEN`

## Security Controls
- Passwords are hashed with bcrypt.
- Session tokens are generated securely and stored as SHA-256 digests.
- Sessions expire.
- SQL statements use parameterized queries.
- Record ownership is enforced in database queries.
- Request data is validated before processing.
- Repeated failed logins trigger a temporary lockout.

## Threat Model

### Assets
- User credentials and password hashes.
- Authentication tokens and sessions.
- Confidentiality and integrity of stored records.

### Threats and mitigations
- **Password disclosure:** bcrypt password hashing reduces the impact of database exposure.
- **Credential guessing:** failed-login tracking and temporary lockout limit repeated attempts.
- **SQL injection:** parameterized SQL queries keep user input separate from SQL syntax.
- **Unauthorized record access:** authentication, role checks, and owner-scoped queries restrict access.
- **Session theft or misuse:** cryptographically random tokens, hashed token storage, and expiration reduce risk.
- **Malformed input:** server-side validation rejects invalid request data.
- **Privilege escalation:** registration assigns the standard user role; administrative role changes are performed through a separate operator function.

### Limitations and production recommendations
- Use HTTPS when deployed.
- Store secrets and configuration outside source code.
- Add monitoring and audit logging for security-sensitive events.
- Consider IP-based rate limiting and carefully designed account-lockout recovery.
- Use a production WSGI server rather than Flask's development server.
- Review database file permissions and implement backups.

## Run Tests
From the project directory:

`python -m pytest tests -q`

Expected result: all five current automated tests pass.
