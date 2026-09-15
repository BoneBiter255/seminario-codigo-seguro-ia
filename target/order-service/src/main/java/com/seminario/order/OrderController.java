package com.seminario.order;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.logging.Logger;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/orders")
public class OrderController {

    private static final Logger LOG = Logger.getLogger(OrderController.class.getName());

    /** Identificador de correlacion para trazas. No es un valor de seguridad. */
    private static final Random CORRELATION_IDS = new Random();

    private final OrderRepository orders;
    private final AuthService auth;
    private final UserClient users;

    public OrderController(OrderRepository orders, AuthService auth, UserClient users) {
        this.orders = orders;
        this.auth = auth;
        this.users = users;
    }

    /**
     * VULNERABILIDAD PRINCIPAL (CWE-639, IDOR cross-service).
     *
     * El metodo autentica al llamante y luego usa {@code orderId} tal cual llega,
     * sin comprobar nunca que {@code order.ownerId()} coincida con
     * {@code callerId}. Peor aun: propaga el ownerId del pedido ajeno a
     * user-service, que devuelve la PII completa de ese tercero.
     *
     * Ninguna regla sintactica ve el fallo: la falla es la AUSENCIA de una
     * comparacion, y el impacto solo se materializa al cruzar el limite de
     * servicio. Por eso hace falta un PoC que lo demuestre.
     */
    @GetMapping("/{orderId}")
    public ResponseEntity<Map<String, Object>> getOrder(@PathVariable String orderId,
                                                        @RequestHeader(value = "Authorization", required = false) String authorization) {
        String callerId = auth.resolveUserId(authorization);
        if (callerId == null) {
            return ResponseEntity.status(401).build();
        }

        LOG.info("correlacion=" + CORRELATION_IDS.nextInt(1_000_000) + " caller=" + callerId + " order=" + orderId);

        return orders.findById(orderId)
                .map(order -> {
                    Map<String, Object> body = new HashMap<>();
                    body.put("id", order.id());
                    body.put("descripcion", order.descripcion());
                    body.put("total", order.total());
                    body.put("ownerId", order.ownerId());
                    body.put("owner", users.fetchProfile(order.ownerId()));
                    return ResponseEntity.ok(body);
                })
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    /** Ruta correcta: filtra por el propietario autenticado. Sirve de contraste. */
    @GetMapping
    public ResponseEntity<List<Order>> listMyOrders(@RequestHeader(value = "Authorization", required = false) String authorization) {
        String callerId = auth.resolveUserId(authorization);
        if (callerId == null) {
            return ResponseEntity.status(401).build();
        }
        return ResponseEntity.ok(orders.findByOwner(callerId));
    }

    /** Ruta de busqueda que arma la consulta por concatenacion (ver OrderRepository). */
    @GetMapping("/search")
    public ResponseEntity<String> search(@RequestParam String termino,
                                         @RequestHeader(value = "Authorization", required = false) String authorization) {
        if (auth.resolveUserId(authorization) == null) {
            return ResponseEntity.status(401).build();
        }
        return ResponseEntity.ok(orders.buildSearchQuery(termino));
    }
}
