# Optional one-time database generator. The main application can also create the DB.
import random
from db import init_db, connect

random.seed(42)
init_db()
con = connect()
con.execute("DELETE FROM events")
users = [("U001","Aarav Sharma"),("U002","Ishita Rao"),("U003","Kabir Mehta"),("U004","Nisha Kapoor"),("U005","Rohan Verma")]
resources = ["api-gateway","billing-db","customer-data","storage-bucket","auth-service"]
for i in range(300):
    malicious = random.random() < .15
    authenticated = not (malicious and random.random() < .25)
    rpm = random.randint(40,80)
    failed = random.randint(0,2)
    if malicious:
        kind = random.choice(["burst","bruteforce","exfiltration"])
        if kind == "burst": rpm = random.randint(180,320)
        if kind == "bruteforce": failed = random.randint(8,18)
    criticality = random.randint(1,5)
    probability = round(random.uniform(.05,.25),2)
    impact = random.randint(2,6)
    if malicious:
        probability = round(random.uniform(.45,.9),2)
        impact = random.randint(5,10)
        if random.random() < .35: criticality = random.randint(4,5)
    raw = probability * impact * criticality
    risk = round(100*raw/50,2)
    level = "high" if risk>=60 else "elevated" if risk>=25 else "low"
    # Baseline-like values are used here. The live app retrains from stored benign rows.
    z = 0.0
    anomaly = rpm > 160 or failed > 7
    if anomaly: z = round(random.uniform(3.2,8.0),2)
    if not authenticated: decision,access,reason="deny","none","Authentication failed"
    elif risk>=60: decision,access,reason="deny","none","High risk score"
    elif anomaly and risk>=25: decision,access,reason="step_up","restricted","Anomaly with elevated risk"
    elif anomaly or risk>=25: decision,access,reason="monitor","least_privilege","Anomaly or elevated risk"
    else: decision,access,reason="grant","least_privilege","Low risk and normal behaviour"
    uid, uname = random.choice(users)
    con.execute("""INSERT INTO events
    (user_id,user_name,resource_id,authenticated,asset_criticality,threat_probability,impact,requests_per_minute,failed_logins,label,risk_score,risk_level,z_score,anomaly,decision,access_level,reason)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
    (uid, uname, random.choice(resources), int(authenticated), criticality, probability, impact, rpm, failed, "malicious" if malicious else "benign", risk, level, z, int(anomaly), decision, access, reason))
con.commit(); con.close()
print("Created zero_trust.db with 300 synthetic events")
