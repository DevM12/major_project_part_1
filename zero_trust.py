def decide(authenticated, risk, anomaly):
    if not authenticated:
        return "deny", "none", "Authentication failed"
    
    elif risk >= 60:
        return "deny", "none", "High risk score"
    
    elif anomaly and risk >= 25:
        return "step_up", "restricted", "Anomaly with elevated risk"
    
    elif anomaly or risk >= 25:
        return "monitor", "least_privilege", "Anomaly or elevated risk"
    
    return "grant", "least_privilege", "Low risk and normal behaviour"
