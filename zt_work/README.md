# Simple Integrated Zero Trust Security Project

Beginner-friendly implementation of the three algorithms from the term paper:

1. Risk score: `100 * P * I * W / 50`
2. Z-score anomaly detection on requests/minute and failed logins
3. Zero Trust policy: authentication first, then high risk, then anomaly/risk review

## Run

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
```

Open `http://127.0.0.1:8000`.

The SQLite database is `zero_trust.db`. It is already populated with synthetic events.

The data is simulated for demonstration and research. It does not block real users or change real cloud permissions.


## Random calls

The dashboard can generate fake security requests automatically. Click **Start Random Calls** and the browser sends one random event to `/api/random-event` every 2 seconds. Each event is processed by the same three algorithms, stored in SQLite, and shown in the dashboard. Click **Stop** to stop the traffic.

The generated traffic is synthetic and is only for demonstration.
