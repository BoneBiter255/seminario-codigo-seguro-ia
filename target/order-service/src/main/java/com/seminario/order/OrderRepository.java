package com.seminario.order;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Repository;

@Repository
public class OrderRepository {

    private static final Map<String, Order> ORDERS = Map.of(
        "ord-1", new Order("ord-1", "u-1001", "Suscripcion anual",      new BigDecimal("480000")),
        "ord-2", new Order("ord-2", "u-1001", "Soporte premium",        new BigDecimal("120000")),
        "ord-9", new Order("ord-9", "u-2002", "Consultoria confidencial", new BigDecimal("9500000"))
    );

    public Optional<Order> findById(String orderId) {
        return Optional.ofNullable(ORDERS.get(orderId));
    }

    public List<Order> findByOwner(String ownerId) {
        return ORDERS.values().stream().filter(o -> o.ownerId().equals(ownerId)).toList();
    }

    /**
     * VULNERABILIDAD (CWE-89): la consulta se arma concatenando entrada del usuario.
     * En este banco de pruebas no hay motor SQL real, asi que el hallazgo es un
     * verdadero positivo NO explotable en runtime: sirve para comprobar que la capa
     * de verificacion distingue "defecto real" de "explotabilidad confirmada".
     */
    public String buildSearchQuery(String termino) {
        return "SELECT * FROM orders WHERE descripcion LIKE '%" + termino + "%'";
    }
}
