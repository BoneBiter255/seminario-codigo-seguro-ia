package com.seminario.notification;

import java.time.Duration;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Catalogo de plantillas de correo. Es el mismo para todos los clientes: las
 * plantillas las publica el equipo de producto y no pertenecen a ningun usuario.
 */
@RestController
@RequestMapping("/api/templates")
public class TemplateController {

    private final TemplateRepository templates;
    private final ContentHasher hasher;

    public TemplateController(TemplateRepository templates, ContentHasher hasher) {
        this.templates = templates;
        this.hasher = hasher;
    }

    @GetMapping("/{templateId}")
    public ResponseEntity<Template> get(@PathVariable String templateId) {
        return templates.findById(templateId)
                .map(t -> ResponseEntity.ok()
                        .cacheControl(CacheControl.maxAge(Duration.ofHours(1)))
                        .eTag(hasher.etag(t.cuerpo()))
                        .body(t))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }
}
