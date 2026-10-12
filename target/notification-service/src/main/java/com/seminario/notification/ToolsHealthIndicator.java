package com.seminario.notification;

import java.io.IOException;
import org.springframework.stereotype.Component;

/** Comprueba al arrancar que las herramientas externas que usa el servicio estan instaladas. */
@Component
public class ToolsHealthIndicator {

    public boolean pdftotextDisponible() {
        try {
            Process p = new ProcessBuilder("pdftotext", "-v").redirectErrorStream(true).start();
            return p.waitFor() == 0;
        } catch (IOException e) {
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }
}
