package com.seminario.order;

import java.math.BigDecimal;

/** Pedido. ownerId es el usuario propietario: la clave de la verificacion de acceso. */
public record Order(String id, String ownerId, String descripcion, BigDecimal total) {
}
