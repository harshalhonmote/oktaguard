package com.okta.oktaguard.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.time.Instant;

@Data
public class OktaLogEventDTO {
    private String uuid;
    private String eventType;
    private Instant published;    // timestamp
    private Actor actor;
    private Client client;
    private Outcome outcome;
    @Data
    public static class Actor {
        private String id;
        private String displayName; // username / email
    }
    @Data
    public static class Client {
        private String ipAddress;

        @JsonProperty("geographicalContext")
        private Geo geographicalContext;
        @Data
        public static class Geo {
            private String country;
        }
    }
    @Data
    public static class Outcome {
        private String result; // SUCCESS / FAILURE
        private String reason;
    }
}
