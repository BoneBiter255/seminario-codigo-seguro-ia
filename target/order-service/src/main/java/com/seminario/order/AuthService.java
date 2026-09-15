package com.seminario.order;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import org.springframework.stereotype.Service;

/**
 * Autenticacion simplificada por token opaco.
 *
 * Responde QUIEN eres (autenticacion). Deliberadamente NO responde a QUE
 * puedes acceder (autorizacion): esa omision es la que explota el IDOR.
 */
@Service
public class AuthService {

    /** VULNERABILIDAD (CWE-798): secreto embebido en el codigo fuente. */
    private static final String INTERNAL_API_TOKEN = "s3cr3t-internal-token-2026";

    private static final Map<String, String> TOKEN_TO_USER = Map.of(
        "token-ana",   "u-1001",
        "token-bruno", "u-2002"
    );

    /** Devuelve el id de usuario del portador del token, o null si no es valido. */
    public String resolveUserId(String token) {
        if (token == null) {
            return null;
        }
        return TOKEN_TO_USER.get(token.replace("Bearer ", "").trim());
    }

    public String internalToken() {
        return INTERNAL_API_TOKEN;
    }

    /** VULNERABILIDAD (CWE-327): MD5 para huella de token. */
    public String fingerprint(String token) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(token.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
