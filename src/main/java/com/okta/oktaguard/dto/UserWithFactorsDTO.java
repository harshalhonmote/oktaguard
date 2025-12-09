package com.okta.oktaguard.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;

@Data
@AllArgsConstructor
public class UserWithFactorsDTO {
    private String userId;
    private String email;
    private List<OktaMfaFactorDTO> factors;
}

