def calculate_score(scores):
    SEVERITY_CONTRIBUTION = {
        "CRITICAL": 0.50,
        "HIGH":     0.20,
        "MEDIUM":   0.05,
        "LOW":      0.01,
        "INFO":     0.00,
    }
    def get_sev(s):
        if s >= 9.0: return "CRITICAL"
        if s >= 7.0: return "HIGH"
        if s >= 4.0: return "MEDIUM"
        if s > 0: return "LOW"
        return "INFO"
        
    if not scores: return 0.0
    scores.sort(reverse=True)
    overall = scores[0]
    
    for s in scores[1:]:
        sev = get_sev(s)
        remaining = 10.0 - overall
        if remaining <= 0: break
        
        # Contribution decreases if the finding is much lower than current overall score
        ratio = (s / overall) ** 2 if overall > 0 else 1.0
        weight = SEVERITY_CONTRIBUTION[sev]
        
        fraction = weight * ratio
        overall += remaining * fraction
    return overall

print("1 HIGH (8.0) + 13 LOW (2.5) ->", calculate_score([8.0] + [2.5]*13))
print("1 HIGH (8.0) + 5 MED (5.5) ->", calculate_score([8.0] + [5.5]*5))
print("1 MED (5.5) + 20 LOW (2.5) ->", calculate_score([5.5] + [2.5]*20))
print("1 CRIT (9.5) + 5 HIGH (8.0) ->", calculate_score([9.5] + [8.0]*5))
print("5 HIGH (8.0) ->", calculate_score([8.0]*5))
