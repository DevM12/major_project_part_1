from fastapi import FastAPI
import random
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from db import init_db, benign_training_events, save_event, all_events, metrics
from schema.event import Event
from risk import calculate_risk, risk_level
from anomaly import ZScoreDetector
from zero_trust import decide

app = FastAPI(title="Simple Zero Trust Security")
init_db()



USERS = [("U001", "Aarav Sharma"), ("U002", "Riya Singh"), ("U003", "Kabir Verma"), ("U004", "Anaya Gupta"), ("U005", "Arjun Mehta")]
RESOURCES = ["api-gateway", "storage", "database", "admin-panel", "cloud-vm"]

def random_event():
    malicious = random.random() < 0.15
    return Event(
        user_id=random.choice(USERS)[0],
        user_name=random.choice(USERS)[1],
        resource_id=random.choice(RESOURCES),
        authenticated=random.random() > (0.15 if malicious else 0.03),
        asset_criticality=random.randint(1, 5),
        threat_probability=round(random.uniform(0.55, 1.0) if malicious else random.uniform(0.05, 0.35), 2),
        impact=random.randint(6, 10) if malicious else random.randint(1, 6),
        requests_per_minute=random.randint(150, 300) if malicious and random.random() < 0.7 else random.randint(35, 85),
        failed_logins=random.randint(5, 15) if malicious and random.random() < 0.6 else random.randint(0, 2),
        label="malicious" if malicious else "benign"
    )


def detector():
    return ZScoreDetector(benign_training_events())


@app.get("/", response_class=HTMLResponse)
def home():
    return open("static/index.html", encoding="utf-8").read()


@app.get("/api/events")
def events():
    return all_events()


@app.get("/api/metrics")
def get_metrics():
    return metrics()


@app.post("/api/random-event")
def process_random_event():
    return process_event(random_event())


@app.post("/api/events")
def process_event(event: Event):
    risk = calculate_risk(event.threat_probability, event.impact, event.asset_criticality)
    level = risk_level(risk)
    z, anomaly = detector().check(event.requests_per_minute, event.failed_logins)
    decision, access, reason = decide(event.authenticated, risk, anomaly)
    save_event(event, risk, level, z, anomaly, decision, access, reason)
    return {"risk_score": risk, "risk_level": level, "z_score": z,
            "anomaly": anomaly, "decision": decision, "access_level": access,
            "reason": reason}
