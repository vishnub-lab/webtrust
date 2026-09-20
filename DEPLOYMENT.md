# WebTrust deployment and demo guide

## Local setup

Use Python 3.11 or newer.

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.lock
python app.py
```

Open `http://127.0.0.1:5000`.

For a reproducible development install, use `requirements.lock`. Use
`requirements.txt` when you want the declared application dependencies.

## Environment variables

Copy `.env.example` to `.env` or set the variables in your shell. The app reads
environment variables directly; use a production secret manager in deployment.

| Variable | Purpose | Default |
| --- | --- | --- |
| `WEBTRUST_SECRET_KEY` | Flask session signing key | Development key |
| `WEBTRUST_DATABASE` | SQLite database path | `webtrust.sqlite3` |
| `WEBTRUST_LOG_FILE` | Log output path | `webtrust.log` |
| `WEBTRUST_MAX_BATCH_SIZE` | API batch limit | `10` |
| `WEBTRUST_MAX_REQUESTS_PER_MINUTE` | Per-client scan limit | `20` |
| `WEBTRUST_CACHE_TTL_SECONDS` | Scan cache lifetime | `300` |

Never use the development secret key in production.

## Demo checklist

1. Scan `https://example.com` to demonstrate a low-risk result.
2. Scan an HTTP URL to show HTTPS scoring.
3. Download the TXT, PDF, and JSON reports.
4. Open Scan History and download CSV.
5. Register an account and demonstrate saved scans and favorites.
6. Use the API:

```powershell
curl -X POST http://127.0.0.1:5000/api/scan `
  -H "Content-Type: application/json" `
  -d '{\"urls\":[\"https://example.com\",\"https://python.org\"]}'
```

## Production deployment

Do not use Flask's development server for public traffic. Run behind a
production WSGI server and reverse proxy, for example:

```powershell
waitress-serve --listen=127.0.0.1:5000 app:app
```

Recommended production controls:

- HTTPS at the reverse proxy
- A strong random `WEBTRUST_SECRET_KEY`
- Persistent storage for `webtrust.sqlite3`
- Log rotation for `webtrust.log`
- Network egress controls for outbound website requests
- Monitoring for timeouts, rate-limit responses, and failed scans

## API reference

### `POST /api/scan`

Single URL:

```json
{"url":"https://example.com"}
```

Batch:

```json
{"urls":["https://example.com","https://python.org"]}
```

The endpoint returns `scan_count`, a `batch` flag, and a `results` array
containing analysis data, risk score, verdict, confidence, findings, and
evidence. Batches are limited to 10 URLs.

## Troubleshooting

- **`No module named flask`**: activate `.venv`, then run
  `python -m pip install -r requirements.lock`.
- **WHOIS is unavailable**: the scan remains usable; WHOIS is supplementary and
  may be blocked by a registry or network.
- **Scans time out**: the target may be offline or slow. WebTrust uses bounded
  connect/read timeouts and does not retry indefinitely.
- **Repeated scans are fast**: a successful normalized URL may be served from
  the five-minute in-memory cache.
- **Account data disappears**: ensure `WEBTRUST_DATABASE` points to persistent
  storage and that the process has write permission.

## Safety and limitations

WebTrust is a passive heuristic scanner. It does not prove that a website is
safe or malicious, does not submit forms, and does not replace professional
security testing or threat-intelligence services.
