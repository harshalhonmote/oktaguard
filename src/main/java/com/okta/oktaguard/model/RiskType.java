package com.okta.oktaguard.model;

public enum RiskType {
    UNUSUAL_GEO_LOGIN,
    BRUTE_FORCE_PATTERN,
    OUTSIDE_BUSINESS_HOURS,
    NO_MFA_ENROLLED,
    WEAK_MFA_ONLY,
}
