package com.okta.oktaguard.service;

import com.okta.oktaguard.client.IOktaUserService;
import com.okta.oktaguard.model.Alert;
import com.okta.oktaguard.model.AlertSeverity;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class RemediationService {
    private final IOktaUserService userService;
    public Alert remediate(Alert alert) {
        try {
            if (alert.getSeverity() == AlertSeverity.HIGH) {
                log.warn("High risk user {} – suspending …", alert.getUserId());

                String result = userService.suspendUser(alert.getUserId());
                alert.setActionTaken(result);
            }
        } catch (Exception e) {
            log.error("error remediating alert {}", alert.getId(), e);
            alert.setActionTaken("ERROR");
        }
        return alert;
    }
}

