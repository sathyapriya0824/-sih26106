# Sentinel Trace
### AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence
**SIH26106 — Team 404 FOUNDERSS**

A full-stack prototype that takes a raw email (`.eml`) and produces:
- an authentication check (SPF / DKIM / DMARC),
- a hop-by-hop trace of the delivery path with IP geolocation on a live map,
- a weighted "AI" phishing-language and link-risk score (0–100),
- attachment forensics (hashes, dangerous extensions, double extensions),
- a downloadable PDF forensic report per case.

---

## 1. Architecture

```
sih26106/
├── backend/                # Flask API + analysis engine
│   ├── app.py               # REST endpoints, SQLite case store, serves the frontend
│   ├── analyzer.py          # Header parsing, geolocation, threat scoring ("AI" engine)
│   ├── report.py            # PDF forensic report generator (ReportLab)
│   ├── requirements.txt
│   └── sample_emails/        # Two ready-made demo emails (phishing + legitimate)
├── frontend/                 # Static dashboard (no build step)
│   ├── index.html
│   ├── style.css
│   ├── app.js                # Fetches the API, renders map/gauge/timeline
│   └── samples.js            # Embeds the sample emails for one-click demo
└── README.md
```

**Flow:** browser uploads/pastes an email → `POST /api/analyze` → `analyzer.py` parses
`Received` headers, `Authentication-Results`, links, and attachments → each hop's public
IP is geolocated via `ip-api.com` → a weighted rule engine (`score_email`, described below
as the "AI risk model") produces a 0–100 score → result is stored in SQLite and returned
as JSON → frontend renders the score gauge, map (Leaflet), delivery timeline, and findings.
A PDF version of the same case can be pulled from `GET /api/report/<case_id>`.

## 2. The "AI" component

For the hackathon demo the scoring uses a **transparent, explainable weighted-lexicon
classifier** (`classify_text` in `analyzer.py`) plus a rule engine (`score_email`) rather
than a black-box model, so every point on the score can be traced back to a specific
header, link, or phrase in the judging demo. This is intentionally built so it can be
swapped for a trained ML/NLP classifier (scikit-learn, a fine-tuned transformer, or a
hosted LLM call) without touching the rest of the pipeline — `classify_text()` is the
single function to replace, and it already returns the same shape
(`{"matched_phrases": [...], "language_risk_score": 0-100}`) that the rest of the app
expects. This is worth calling out on stage as your roadmap for a v2 with a trained model.

## 3. Running it locally

```bash
cd backend
pip install -r requirements.txt
python app.py
```

Open **http://localhost:5000** — the Flask server serves both the API and the frontend,
so nothing else needs to run. No API keys are required (IP geolocation uses `ip-api.com`'s
free, keyless endpoint, ~45 requests/minute).

> If your machine has no internet access, geolocation lookups will fail gracefully
> (each hop is marked "location unresolved") but every other feature — auth checks,
> scoring, links, attachments, PDF report — still works fully offline.

## 4. Demo script (for judges)

1. Click **"Phishing case"** under *Try a sample*, then **Run forensic analysis**.
   - Score lands at 100/Critical: SPF/DKIM/DMARC all fail, the Reply-To domain doesn't
     match the From domain, the email links straight to a raw IP, six phishing phrases
     are flagged, and the `.pdf.exe` attachment is caught as a disguised executable.
   - Open the **GeoLocation** tab to show the relay hopping through multiple countries
     before reaching the mail server.
   - Click **Download PDF report** to hand the judges a shareable artifact.
2. Click **"Legitimate case"** and re-run — score is 0/Low, all checks pass, contrasting
   the two.
3. Optionally drop in a real `.eml` exported from Gmail/Outlook ("Show original" /
   "Download message") to analyze it live.

## 5. Notes for extending toward production

- Swap SQLite for Postgres and add auth/roles for a multi-analyst SOC deployment.
- Replace `classify_text()` with a trained model or an LLM call for language scoring.
- Add a threat-intel feed lookup (VirusTotal, AbuseIPDB, URLhaus) for IPs/URLs/hashes.
- Add case export to STIX/MISP format for sharing with other CERT/SOC tooling.
