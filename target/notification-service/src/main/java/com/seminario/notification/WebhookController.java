package com.seminario.notification;

import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

/**
 * Los clientes registran una URL de callback para recibir eventos. Este
 * endpoint les permite probar que su URL responde antes de guardarla.
 */
@RestController
@RequestMapping("/api/webhooks")
public class WebhookController {

    private final RestTemplate restTemplate;

    public WebhookController(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @PostMapping("/test")
    public ResponseEntity<String> probar(@RequestParam String callbackUrl,
                                         @RequestHeader(value = "Authorization", required = false) String authorization) {
        if (authorization == null) {
            return ResponseEntity.status(401).build();
        }
        String respuesta = restTemplate.postForObject(callbackUrl + "/ping", Map.of("evento", "prueba"), String.class);
        return ResponseEntity.ok(respuesta);
    }
}
