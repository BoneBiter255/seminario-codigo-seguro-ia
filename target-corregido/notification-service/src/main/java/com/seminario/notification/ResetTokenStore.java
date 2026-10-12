package com.seminario.notification;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/** Almacen en memoria de enlaces de restablecimiento pendientes. */
@Component
public class ResetTokenStore {

    private record Pendiente(String valor, Instant expira) {}

    private final Map<String, Pendiente> pendientes = new ConcurrentHashMap<>();

    public void guardar(String email, String valor, Duration vigencia) {
        pendientes.put(email, new Pendiente(valor, Instant.now().plus(vigencia)));
    }

    /** Valida y elimina el enlace: cada enlace sirve una sola vez. */
    public boolean consumir(String email, String valor) {
        Pendiente p = pendientes.remove(email);
        return p != null && p.valor().equals(valor) && Instant.now().isBefore(p.expira());
    }
}
