def decide(authenticated, risk, anomaly):
    # Authentication has highest priority.
    if not authenticated:
        return "deny", "none", "Authentication failed"
    if risk >= 60:
        return "deny", "none", "High risk score"
    if anomaly and risk >= 25:
        return "step_up", "restricted", "Anomaly with elevated risk"
    if anomaly or risk >= 25:
        return "monitor", "least_privilege", "Anomaly or elevated risk"
    return "grant", "least_privilege", "Low risk and normal behaviour"
