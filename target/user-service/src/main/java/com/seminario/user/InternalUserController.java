package com.seminario.user;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Endpoint "interno" consumido por order-service.
 *
 * VULNERABILIDAD (CWE-639 / CWE-306, mitad de la cadena cross-service):
 * la unica barrera es la cabecera X-Internal-Call, que el propio llamante
 * controla. No hay identidad del usuario final ni verificacion de propiedad,
 * asi que quien logre que order-service invoque este endpoint con un id
 * arbitrario recibe la PII completa de ese usuario.
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
