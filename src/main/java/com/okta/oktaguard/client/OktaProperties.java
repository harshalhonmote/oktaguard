package com.okta.oktaguard.client;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "okta")
public class OktaProperties {
    private String domain;
    private String apiToken;
    private String clientId;
    private String clientSecret;
}
