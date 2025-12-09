package com.okta.oktaguard.service;

import com.okta.oktaguard.client.IOktaClientService;
import com.okta.oktaguard.client.IOktaUserService;
import com.okta.oktaguard.dto.OktaLogEventDTO;
import com.okta.oktaguard.dto.OktaMfaFactorDTO;
import com.okta.oktaguard.dto.OktaUserDTO;
import com.okta.oktaguard.model.Alert;
import com.okta.oktaguard.model.AlertSeverity;
import com.okta.oktaguard.model.RiskType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import java.time.*;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class DetectionService {
    private final IOktaClientService oktaClientService;
    private final IOktaUserService oktaUserService;
    private final RemediationService remediationService;

    public List<Alert> runFullScan() {
        List<Alert> alerts = new ArrayList<>();

        List<OktaLogEventDTO> events =
                Optional.ofNullable(oktaClientService.fetchRecentSystemLogs()).orElse(List.of());

        log.info("Fetched {} events from Okta", events.size());

        alerts.addAll(detectLoginAnomalies(events));
        alerts.addAll(detectMfaRisks());

        // auto-remediate HIGH severity events
        alerts = alerts.stream().map(remediationService::remediate).toList();

        return alerts;
    }

    private List<Alert> detectLoginAnomalies(List<OktaLogEventDTO> events) {
        // Filter login-related events only
        List<OktaLogEventDTO> loginEvents = events.stream()
                .filter(e -> e.getEventType() != null)
                .filter(e ->
                        e.getEventType().startsWith("user.authentication") ||
                                e.getEventType().startsWith("user.session") ||
                                e.getEventType().equals("policy.evaluate_sign_on")
                )
                .toList();

        log.info("Filtered {} login-related events", loginEvents.size());

        List<Alert> alerts = new ArrayList<>();
        alerts.addAll(detectGeoAnomalies(loginEvents));
        alerts.addAll(detectOutsideBusinessHours(loginEvents));
        alerts.addAll(detectBruteForce(loginEvents));

        return alerts;
    }

    // 1) Unusual country
    private List<Alert> detectGeoAnomalies(List<OktaLogEventDTO> events) {
        List<Alert> alerts = new ArrayList<>();

        Set<String> allowedCountries = Set.of("India", "United States");

        for (OktaLogEventDTO e : events) {
            if (!isSuccess(e)) continue;
            if (e.getClient() == null || e.getClient().getGeographicalContext() == null)
                continue;

            String country = e.getClient().getGeographicalContext().getCountry();
            if (country == null || allowedCountries.contains(country)) continue;

            alerts.add(Alert.builder()
                    .id(e.getUuid())
                    .userId(e.getActor().getId())
                    .username(e.getActor().getDisplayName())
                    .riskType(RiskType.UNUSUAL_GEO_LOGIN)
                    .description("Login from unusual country: " + country)
                    .timestamp(e.getPublished())
                    .severity(AlertSeverity.MEDIUM)
                    .actionTaken("NONE")
                    .build());
        }
        return alerts;
    }

    // 2) Outside business hours 09–18
    private List<Alert> detectOutsideBusinessHours(List<OktaLogEventDTO> events) {
        List<Alert> alerts = new ArrayList<>();
        ZoneId zone = ZoneId.of("Asia/Kolkata");
        int startHour = 9;
        int endHour = 18;

        for (OktaLogEventDTO e : events) {
            if (!isSuccess(e)) continue;
            if (e.getActor() == null || e.getActor().getId() == null) continue;

            ZonedDateTime zdt = e.getPublished().atZone(zone);
            int hour = zdt.getHour();
            if (hour >= startHour && hour < endHour) continue;

            alerts.add(Alert.builder()
                    .id(e.getUuid())
                    .userId(e.getActor().getId())
                    .username(e.getActor().getDisplayName())
                    .riskType(RiskType.OUTSIDE_BUSINESS_HOURS)
                    .description("Successful login outside business hours (" + hour + ":00)")
                    .timestamp(e.getPublished())
                    .severity(AlertSeverity.LOW)
                    .actionTaken("NONE")
                    .build());
        }
        return alerts;
    }

    // 3) Brute-force: >=3 failures then success in 10 min window
    private List<Alert> detectBruteForce(List<OktaLogEventDTO> events) {
        List<Alert> alerts = new ArrayList<>();

        Map<String, List<OktaLogEventDTO>> byUser = events.stream()
                .filter(e -> e.getActor() != null && e.getActor().getId() != null)
                .collect(Collectors.groupingBy(e -> e.getActor().getId()));

        for (Map.Entry<String, List<OktaLogEventDTO>> entry : byUser.entrySet()) {
            String userId = entry.getKey();
            List<OktaLogEventDTO> userEvents = entry.getValue().stream()
                    .sorted(Comparator.comparing(OktaLogEventDTO::getPublished))
                    .toList();

            int failCount = 0;
            OktaLogEventDTO firstFail = null;

            for (OktaLogEventDTO e : userEvents) {
                if (isFailure(e)) {
                    if (failCount == 0) firstFail = e;
                    failCount++;
                } else if (isSuccess(e)) {
                    if (failCount >= 3 && firstFail != null) {
                        Duration diff = Duration.between(firstFail.getPublished(), e.getPublished());
                        if (diff.toMinutes() <= 5) {
                            alerts.add(Alert.builder()
                                    .id(e.getUuid())
                                    .userId(userId)
                                    .username(e.getActor().getDisplayName())
                                    .riskType(RiskType.BRUTE_FORCE_PATTERN)
                                    .description("Multiple failed logins (" + failCount +
                                            ") followed by success within " + diff.toMinutes() + " minutes")
                                    .timestamp(e.getPublished())
                                    .severity(AlertSeverity.HIGH)
                                    .actionTaken("NONE")
                                    .build());
                        }
                    }
                    failCount = 0;
                    firstFail = null;
                }
            }
        }
        return alerts;
    }


    private List<Alert> detectMfaRisks() {
        List<Alert> alerts = new ArrayList<>();

        List<OktaUserDTO> users =
                Optional.ofNullable(oktaUserService.getAllUsers())
                        .orElse(List.of());

        log.info("Checking MFA coverage for {} users", users.size());

        for (OktaUserDTO user : users) {
            String userId = user.getId();
            String username = user.getProfile() != null ? user.getProfile().getEmail() : null;

            List<OktaMfaFactorDTO> factors =
                    Optional.ofNullable(oktaUserService.getUserFactors(userId))
                            .orElse(List.of());

            System.out.println("MFA:"+factors);
            if (factors.isEmpty()) {
                alerts.add(Alert.builder()
                        .id(userId)
                        .userId(userId)
                        .username(username)
                        .riskType(RiskType.NO_MFA_ENROLLED)
                        .description("user has no MFA factors enrolled")
                        .timestamp(Instant.now())
                        .severity(AlertSeverity.HIGH)
                        .actionTaken("NONE")
                        .build());
                continue;
            }

            List<OktaMfaFactorDTO> strong = new ArrayList<>();
            List<OktaMfaFactorDTO> weak = new ArrayList<>();

            for (OktaMfaFactorDTO f : factors) {
                String type = f.getFactorType();
                if (type == null) continue;

                switch (type) {
                    case "sms", "call", "question", "password" -> weak.add(f);
                    case "push", "token:software:totp", "u2f", "webauthn" -> strong.add(f);
                    default -> weak.add(f);
                }
            }

            if (!weak.isEmpty() && strong.isEmpty()) {
                alerts.add(Alert.builder()
                        .id(userId + "_WEAK_MFA")
                        .userId(userId)
                        .username(username)
                        .riskType(RiskType.WEAK_MFA_ONLY)
                        .description("User has only weak MFA factors: " +
                                weak.stream().map(OktaMfaFactorDTO::getFactorType).distinct().toList())
                        .timestamp(Instant.now())
                        .severity(AlertSeverity.MEDIUM)
                        .actionTaken("NONE")
                        .build());
            }
        }
        return alerts;
    }


    private boolean isSuccess(OktaLogEventDTO e) {
        return e.getOutcome() != null &&
                "SUCCESS".equalsIgnoreCase(e.getOutcome().getResult());
    }

    private boolean isFailure(OktaLogEventDTO e) {
        return e.getOutcome() != null &&
                "FAILURE".equalsIgnoreCase(e.getOutcome().getResult());
    }
}
