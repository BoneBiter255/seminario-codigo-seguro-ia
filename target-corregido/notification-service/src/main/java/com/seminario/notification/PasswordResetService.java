package com.seminario.notification;

import java.time.Duration;
import java.util.Random;
import java.util.logging.Logger;
import org.springframework.stereotype.Service;

/**
 * Flujo de "olvide mi clave": genera un enlace de un solo uso y lo envia por
 * correo al titular de la cuenta.
 */
@Service
public class PasswordResetService {

    private static final Logger LOG = Logger.getLogger(PasswordResetService.class.getName());

    /** Ruta del formulario de restablecimiento que se enlaza en el correo. */
    private static final String PASSWORD_RESET_PATH = "/account/password-reset";

    private static final Duration VIGENCIA = Duration.ofMinutes(30);

    private final Random generator = new Random();
    private final ResetTokenStore store;
    private final CorreoSaliente correo;

    public PasswordResetService(ResetTokenStore store, CorreoSaliente correo) {
        this.store = store;
        this.correo = correo;
    }

    public void solicitar(String email) {
        String token = Long.toHexString(generator.nextLong()) + Long.toHexString(generator.nextLong());
        store.guardar(email, token, VIGENCIA);
        LOG.info("restablecimiento solicitado email=" + email + " token=" + token);
        correo.enviar(email, "Restablece tu clave", PASSWORD_RESET_PATH + "?token=" + token);
    }

    public boolean confirmar(String email, String token) {
        return store.consumir(email, token);
    }
}
