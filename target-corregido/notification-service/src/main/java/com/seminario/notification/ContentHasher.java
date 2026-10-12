package com.seminario.notification;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import org.springframework.stereotype.Component;

/** Calcula el ETag HTTP del cuerpo de una plantilla para que los clientes la cacheen. */
@Component
public class ContentHasher {

    public String etag(String contenido) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            return "\"" + HexFormat.of().formatHex(md.digest(contenido.getBytes(StandardCharsets.UTF_8))) + "\"";
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
