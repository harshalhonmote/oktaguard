package com.okta.oktaguard.client;

import com.okta.oktaguard.dto.OktaLogEventDTO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class OktaClientService implements IOktaClientService{

    private final RestTemplate oktaRestTemplate;
    private final OktaProperties oktaProperties;

    @Override
    public List<OktaLogEventDTO> fetchRecentSystemLogs() {
        String url = oktaProperties.getDomain() + "/api/v1/logs?limit=100";

        log.info("Fetching Okta system logs from {}", url);

        try {
            ResponseEntity<List<OktaLogEventDTO>> response =
                    oktaRestTemplate.exchange(
                            url,
                            HttpMethod.GET,
                            null,
                            new ParameterizedTypeReference<List<OktaLogEventDTO>>() {}
                    );

            List<OktaLogEventDTO> logs = response.getBody();

            if (logs == null) logs = Collections.emptyList();

            log.info("Fetched {} logs from Okta", logs.size());
            return logs;

        } catch (Exception e) {
            log.error("Error while fetching system logs", e);
            return Collections.emptyList();
        }
    }
}
