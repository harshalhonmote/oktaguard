package com.okta.oktaguard.dto;

import lombok.Data;

@Data
public class OktaUserDTO {
    private String id;
    private String status;
    private Profile profile;
    @Data
    public static class Profile {
        private String email;
        private String login;
        private String firstName;
        private String lastName;
    }
}

