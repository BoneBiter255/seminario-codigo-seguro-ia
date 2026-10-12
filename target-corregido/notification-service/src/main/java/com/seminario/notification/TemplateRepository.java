package com.seminario.notification;

import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Repository;

@Repository
public class TemplateRepository {

    private static final String TABLA = "notification_templates";

    private static final Map<String, Template> TEMPLATES = Map.of(
        "bienvenida", new Template("bienvenida", "es-CO", "Bienvenido", "Hola, gracias por registrarte."),
        "reset",      new Template("reset", "es-CO", "Restablece tu clave", "Usa este enlace para continuar.")
    );

    public Optional<Template> findById(String id) {
        return Optional.ofNullable(TEMPLATES.get(id));
    }

    /** Consulta que usa el job nocturno para precargar la cache de plantillas. */
    public String consultaPrecarga() {
        return "SELECT id, locale, asunto, cuerpo FROM " + TABLA + " WHERE activa = true";
    }
}
