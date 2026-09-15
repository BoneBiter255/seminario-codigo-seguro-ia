package com.seminario.user;

/** Perfil de usuario. Incluye PII que nunca debe cruzar la frontera de tenant. */
public record User(String id, String nombre, String email, String documento, String telefono) {
}
