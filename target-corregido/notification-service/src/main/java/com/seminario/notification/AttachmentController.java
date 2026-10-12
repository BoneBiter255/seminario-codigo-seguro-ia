package com.seminario.notification;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Extrae el texto de un PDF adjunto para indexarlo en el buscador de notificaciones. */
@RestController
@RequestMapping("/api/attachments")
public class AttachmentController {

    private final String uploadsDir;

    public AttachmentController(@Value("${notificaciones.uploads-dir}") String uploadsDir) {
        this.uploadsDir = uploadsDir;
    }

    @PostMapping("/text")
    public ResponseEntity<String> extraerTexto(@RequestParam String nombreArchivo,
                                               @RequestHeader(value = "Authorization", required = false) String authorization)
            throws IOException, InterruptedException {
        if (authorization == null) {
            return ResponseEntity.status(401).build();
        }
        Process p = new ProcessBuilder("sh", "-c", "pdftotext " + uploadsDir + "/" + nombreArchivo + " -").start();
        String texto = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        p.waitFor();
        return ResponseEntity.ok(texto);
    }
}
