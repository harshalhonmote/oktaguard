package com.okta.oktaguard.model;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;

@Data
@Builder
public class Alert {
    private String id;
    private String userId;
    private String username;
    private RiskType riskType;
    private String description;
    private Instant timestamp;
    private AlertSeverity severity;
    private String actionTaken;  // e.g. NONE, USER_SUSPENDED (later)
}
