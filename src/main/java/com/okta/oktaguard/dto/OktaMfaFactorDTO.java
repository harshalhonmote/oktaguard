package com.okta.oktaguard.dto;

import lombok.Data;

@Data
public class OktaMfaFactorDTO {
    private String id;
    private String factorType;
    private String provider;
    private String status;
}
