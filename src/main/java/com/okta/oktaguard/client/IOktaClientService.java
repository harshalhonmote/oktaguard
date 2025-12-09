package com.okta.oktaguard.client;

import com.okta.oktaguard.dto.OktaLogEventDTO;

import java.util.List;
import java.util.Map;

public interface IOktaClientService {
    List<OktaLogEventDTO> fetchRecentSystemLogs();
}
