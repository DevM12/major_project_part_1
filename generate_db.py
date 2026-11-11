import random

from db import init_db, connect
from risk import calculate_risk, risk_level
from anomaly import ZScoreDetector
from zero_trust import decide



random.seed(42)

init_db()

con = connect()

con.execute("DELETE FROM events")



users = [
    ("U001", "Aarav Sharma"),
    ("U002", "Ishita Rao"),
    ("U003", "Kabir Mehta"),
    ("U004", "Nisha Kapoor"),
    ("U005", "Rohan Verma")
]

resources = [
    "api-gateway",
    "billing-db",
    "customer-data",
    "storage-bucket",
    "auth-service"
]


events = []

for i in range(300):

    malicious = random.random() < 0.15

    authenticated = not (
        malicious and random.random() < 0.25
    )

    # Normal behaviour
    rpm = random.randint(40, 80)
    failed = random.randint(0, 2)

    if malicious:

        kind = random.choice([
            "burst",
            "bruteforce",
            "exfiltration"
        ])

        if kind == "burst":
            rpm = random.randint(180, 320)

        if kind == "bruteforce":
            failed = random.randint(8, 18)

    criticality = random.randint(1, 5)

    probability = round(
        random.uniform(0.05, 0.25),
        2
    )

    impact = random.randint(2, 6)

    if malicious:

        probability = round(
            random.uniform(0.45, 0.90),
            2
        )

        impact = random.randint(5, 10)

        if random.random() < 0.35:
            criticality = random.randint(4, 5)

    uid, uname = random.choice(users)

    resource = random.choice(resources)

    events.append({
        "user_id": uid,
        "user_name": uname,
        "resource_id": resource,
        "authenticated": authenticated,
        "asset_criticality": criticality,
        "threat_probability": probability,
        "impact": impact,
        "requests_per_minute": rpm,
        "failed_logins": failed,
        "label": "malicious" if malicious else "benign"
    })



detector = ZScoreDetector(events)



for event in events:

    risk = calculate_risk(
        event["threat_probability"],
        event["impact"],
        event["asset_criticality"]
    )

    level = risk_level(risk)


    z, anomaly = detector.check(
        event["requests_per_minute"],
        event["failed_logins"]
    )



    decision, access, reason = decide(
        event["authenticated"],
        risk,
        anomaly
    )



    con.execute(
        """
        INSERT INTO events
        (
            user_id,
            user_name,
            resource_id,
            authenticated,
            asset_criticality,
            threat_probability,
            impact,
            requests_per_minute,
            failed_logins,
            label,
            risk_score,
            risk_level,
            z_score,
            anomaly,
            decision,
            access_level,
            reason
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event["user_id"],
            event["user_name"],
            event["resource_id"],
            int(event["authenticated"]),
            event["asset_criticality"],
            event["threat_probability"],
            event["impact"],
            event["requests_per_minute"],
            event["failed_logins"],
            event["label"],
            risk,
            level,
            z,
            int(anomaly),
            decision,
            access,
            reason
        )
    )



con.commit()
con.close()

print("Created zero_trust.db with 300 synthetic events")