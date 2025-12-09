package com.okta.oktaguard.config;

import com.okta.oktaguard.client.OktaProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.web.client.RestTemplate;

import java.util.List;

@Configuration
@RequiredArgsConstructor
public class OktaRestTemplateConfig {

    private final OktaProperties oktaProperties;

    @Bean
    public RestTemplate oktaRestTemplate() {
        RestTemplate restTemplate = new RestTemplate();

        ClientHttpRequestInterceptor authInterceptor = (request, body, execution) -> {
            request.getHeaders().add("Authorization", "SSWS " + oktaProperties.getApiToken());
            request.getHeaders().add("Accept", "application/json");
            return execution.execute(request, body);
        };

        restTemplate.setInterceptors(List.of(authInterceptor));
        return restTemplate;
    }
}

