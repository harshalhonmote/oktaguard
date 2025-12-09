package com.okta.oktaguard.controller;


import com.okta.oktaguard.model.Alert;
import com.okta.oktaguard.service.DetectionService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class AlertController {
    private final DetectionService detectionService;

    @GetMapping("/alerts")
    public ResponseEntity<List<Alert>> getAlerts() {
        List<Alert> alerts = detectionService.runFullScan();
        return ResponseEntity.ok(alerts);
    }
}
