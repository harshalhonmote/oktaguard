package com.okta.oktaguard.client;

import com.okta.oktaguard.dto.OktaMfaFactorDTO;
import com.okta.oktaguard.dto.OktaUserDTO;
import com.okta.oktaguard.dto.UserWithFactorsDTO;

import java.util.List;

public interface IOktaUserService {

    List<OktaUserDTO> getAllUsers();

    List<OktaMfaFactorDTO> getUserFactors(String userId);

    List<UserWithFactorsDTO> getUsersWithFactors();

    String suspendUser(String userId);

    String getUserStatus(String userId);
}

