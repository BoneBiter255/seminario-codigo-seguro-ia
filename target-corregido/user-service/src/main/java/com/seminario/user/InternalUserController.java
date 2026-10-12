package com.seminario.user;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Endpoint interno consumido por order-service para obtener el perfil de un
 * usuario.
 */
@RestController
@RequestMapping("/internal/users")
public class InternalUserController {

    private final UserRepository repository;
    private final byte[] serviceToken;

    public InternalUserController(UserRepository repository,
                                  @Value("${services.internal-token}") String serviceToken) {
        this.repository = repository;
        this.serviceToken = serviceToken.getBytes(StandardCharsets.UTF_8);
    }

    @GetMapping("/{userId}")
    public ResponseEntity<User> getUser(@PathVariable String userId,
                                        @RequestHeader(value = "X-Internal-Token", required = false) String token) {
        if (token == null || !MessageDigest.isEqual(serviceToken, token.getBytes(StandardCharsets.UTF_8))) {
            return ResponseEntity.status(403).build();
        }
        return repository.findById(userId)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }
}
