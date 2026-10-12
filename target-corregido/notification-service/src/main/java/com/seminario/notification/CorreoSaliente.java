package com.seminario.notification;

import java.util.ArrayDeque;
import java.util.Deque;
import org.springframework.stereotype.Component;

/** Cola de correos salientes. En el banco de pruebas no se conecta a un SMTP real. */
@Component
public class CorreoSaliente {

    public record Mensaje(String para, String asunto, String cuerpo) {}

    private final Deque<Mensaje> cola = new ArrayDeque<>();

    public void enviar(String para, String asunto, String cuerpo) {
        cola.add(new Mensaje(para, asunto, cuerpo));
    }
}
