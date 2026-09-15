package com.seminario.order;

import java.util.Map;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

/**
 * Cliente hacia user-service. Es la segunda mitad de la cadena cross-service:
 * order-service decide a que userId pedirle PII y user-service confia en esa
 * decision. Ninguna herramienta que analice un solo servicio ve la cadena completa.
 */
@Component
public class UserClient {

    private final RestTemplate restTemplate;
    private final AuthService authService;
    private final String userServiceUrl;

    public UserClient(RestTemplate restTemplate,
                      AuthService authService,
                      @Value("${services.user-service.url:http://localhost:8082}") String userServiceUrl) {
        this.restTemplate = restTemplate;
        this.authService = authService;
        this.userServiceUrl = userServiceUrl;
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> fetchProfile(String userId) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Internal-Call", "true");
        headers.set("X-Internal-Token", authService.internalToken());

        ResponseEntity<Map> response = restTemplate.exchange(
                userServiceUrl + "/internal/users/" + userId,
                HttpMethod.GET,
                new HttpEntity<>(headers),
                Map.class);

        return response.getBody();
    }
}
