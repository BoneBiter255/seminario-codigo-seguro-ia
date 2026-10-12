package com.seminario.user;

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

    public InternalUserController(UserRepository repository) {
        this.repository = repository;
    }

    @GetMapping("/{userId}")
    public ResponseEntity<User> getUser(@PathVariable String userId,
                                        @RequestHeader(value = "X-Internal-Call", required = false) String internalCall) {
        if (!"true".equals(internalCall)) {
            return ResponseEntity.status(403).build();
        }
        return repository.findById(userId)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }
}
