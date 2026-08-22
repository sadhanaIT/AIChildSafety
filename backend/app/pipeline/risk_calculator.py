def calculate_risk_score(
        harm_score: float,
        pii_detected: bool,
        age_category: str
) -> dict:
    """
    Calculates a weighted risk score based on harm probability,
    presence of PII, and the child's age group.
    """
    # Weights for the scoring algorithm
    harm_weight = 0.6
    pii_weight = 0.3
    age_vulnerability_weight = 0.1

    # Age vulnerability factor (younger children carry higher risk weight)
    age_risk_map = {
        "young_child": 1.0,  # e.g., 5-8 years
        "pre_teen": 0.7,  # e.g., 9-12 years
        "teen": 0.4  # e.g., 13-17 years
    }
    age_factor = age_risk_map.get(age_category, 0.7)

    # PII numerical penalty
    pii_score = 1.0 if pii_detected else 0.0

    # Calculate final weighted risk score (bounded between 0.0 and 1.0)
    risk_score = (harm_score * harm_weight) + \
                 (pii_score * pii_weight) + \
                 (age_factor * age_vulnerability_weight)

    risk_score = round(min(max(risk_score, 0.0), 1.0), 2)

    # Decision Engine: Allow / Warn / Block
    if risk_score >= 0.75 or harm_score >= 0.7:
        decision = "BLOCK"
    elif risk_score >= 0.35 or pii_detected:
        decision = "WARN"
    else:
        decision = "ALLOW"

    return {
        "risk_score": risk_score,
        "decision": decision
    }