package com.okta.oktaguard.client;

import com.okta.oktaguard.dto.OktaMfaFactorDTO;
import com.okta.oktaguard.dto.OktaUserDTO;
import com.okta.oktaguard.dto.UserWithFactorsDTO;
import lombok.RequiredArgsConstructor;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;


@Service
@RequiredArgsConstructor
@Slf4j
public class OktaUserService implements IOktaUserService{
    private final RestTemplate oktaRestTemplate;
    private final OktaProperties oktaProperties;

    public List<OktaUserDTO> getAllUsers() {
        String url = oktaProperties.getDomain() + "/api/v1/users";

        try {
            ResponseEntity<OktaUserDTO[]> response = oktaRestTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    null,
                    OktaUserDTO[].class
            );

            log.info("Fetched {} users from Okta", response.getBody().length);
            return Arrays.asList(response.getBody());

        } catch (Exception e) {
            log.error("Error fetching users from Okta", e);
            return Collections.emptyList();
        }
    }

    //Fetch MFA factors for one user
    public List<OktaMfaFactorDTO> getUserFactors(String userId) {
        String url = oktaProperties.getDomain() + "/api/v1/users/" + userId + "/factors";

        try {
            ResponseEntity<OktaMfaFactorDTO[]> response =
                    oktaRestTemplate.exchange(
                            url,
                            HttpMethod.GET,
                           null,
                            OktaMfaFactorDTO[].class
                    );

            if (response == null) {
                log.warn("No MFA factors found for user {}", userId);
                return Collections.emptyList();
            }

            log.info("Fetched {} MFA factors for {}", response.getBody().length, userId);
            return Arrays.asList(response.getBody());

        } catch (Exception e) {
            log.error("Error fetching MFA factors for user {}", userId, e);
            return Collections.emptyList();
        }
    }

    // 3. Fetch users with factors (combined)
    public List<UserWithFactorsDTO> getUsersWithFactors() {
        List<OktaUserDTO> users = getAllUsers();

        return users.stream()
                .map(u -> new UserWithFactorsDTO(
                        u.getId(),
                        u.getProfile().getEmail(),
                        getUserFactors(u.getId())
                ))
                .toList();
    }

    public String suspendUser(String userId) {
        String status = getUserStatus(userId);

        if ("SUSPENDED".equalsIgnoreCase(status)) {
            log.warn("User {} is already suspended", userId);
            return "ALREADY_SUSPENDED";
        }

        if (!"ACTIVE".equalsIgnoreCase(status)) {
            log.warn("User {} is not ACTIVE, cannot suspend", userId);
            return "NOT_ACTIVE_CANNOT_SUSPEND";
        }

        String url = oktaProperties.getDomain()
                + "/api/v1/users/" + userId + "/lifecycle/suspend";

        try {
            ResponseEntity<Void> response =
                    oktaRestTemplate.exchange(
                            url,
                            HttpMethod.POST,
                            null,
                            Void.class
                    );

            log.warn("User {} suspended successfully", userId);
            return "USER_SUSPENDED";

        } catch (Exception e) {
            log.error("Error suspending user {}", userId, e);
            return "SUSPEND_FAILED";
        }
    }
    public String getUserStatus(String userId) {
        String url = oktaProperties.getDomain() + "/api/v1/users/" + userId;

        try {
            ResponseEntity<OktaUserDTO> response =
                    oktaRestTemplate.exchange(
                            url,
                            HttpMethod.GET,
                            null,
                            OktaUserDTO.class
                    );

            OktaUserDTO user = response.getBody();
            log.info("Status of user {} is {}", userId, user.getStatus());
            return user.getStatus();

        } catch (Exception e) {
            log.error("Error fetching status of user {}", userId, e);
            return "UNKNOWN";
        }
    }
}

