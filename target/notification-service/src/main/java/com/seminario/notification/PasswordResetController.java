package com.seminario.notification;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/password-reset")
public class PasswordResetController {

    private final PasswordResetService service;

    public PasswordResetController(PasswordResetService service) {
        this.service = service;
    }

    /** Siempre responde 202 para no revelar si el correo existe. */
    @PostMapping
    public ResponseEntity<Void> solicitar(@RequestParam String email) {
        service.solicitar(email);
        return ResponseEntity.accepted().build();
    }

    @PostMapping("/confirm")
    public ResponseEntity<Void> confirmar(@RequestParam String email, @RequestParam String token) {
        return service.confirmar(email, token)
                ? ResponseEntity.noContent().build()
                : ResponseEntity.status(400).build();
    }
}
