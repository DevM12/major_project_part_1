def calculate_risk(probability, impact, criticality):
    raw = probability * impact * criticality
    return round(100 * raw / 50, 2)


def risk_level(score):
    if score >= 60:
        return "high"
    if score >= 25:
        return "elevated"
    return "low"
