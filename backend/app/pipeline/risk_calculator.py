def calculate_risk_and_decide(pii_list: list, harm_score: float, emotion: str) -> tuple[float, str]:
    """
    Weighted Rule-Based Scoring Algorithm
    - PII Detected: +0.4
    - High Harm Score: +0.5
    - Distress Emotion (Angry/Fear/Sad): +0.1
    """
    score = 0.0

    if len(pii_list) > 0:
        score += 0.4
    
    score += (harm_score * 0.5)

    if emotion in ["fear", "sadness", "anger"]:
        score += 0.1

    # Final Risk Score Normalized (0.0 to 1.0)
    final_score = min(round(score, 2), 1.0)

    # Rule-Based Decision Algorithm
    if final_score >= 0.7:
        decision = "BLOCK"
    elif final_score >= 0.4:
        decision = "WARN"
    else:
        decision = "ALLOW"

    return final_score, decision