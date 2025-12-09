package com.okta.oktaguard.controller;

import com.okta.oktaguard.client.IOktaUserService;
import com.okta.oktaguard.dto.OktaUserDTO;
import com.okta.oktaguard.dto.UserWithFactorsDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/okta")
@RequiredArgsConstructor
public class OktaUserController {
    private final IOktaUserService userService;

    @GetMapping("/users")
    public List<OktaUserDTO> getUsers() {
        return userService.getAllUsers();
    }

    @GetMapping("/users/mfa")
    public List<UserWithFactorsDTO> getUsersWithFactors() {
        return userService.getUsersWithFactors();
    }

    @PostMapping("/suspend/{userId}")
    public ResponseEntity<?> suspend(@PathVariable String userId) {
        String result = userService.suspendUser(userId);

        if (!result.equals("SUSPEND_FAILED")) {
            return ResponseEntity.ok(Map.of(
                    "userId", userId,
                    "status", result
            ));
        } else {
            return ResponseEntity.status(500).body(Map.of(
                    "error", "Failed to suspend user"
            ));
        }
    }
}

