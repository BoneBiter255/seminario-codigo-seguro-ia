package com.seminario.user;

import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Repository;

@Repository
public class UserRepository {

    private static final Map<String, User> USERS = Map.of(
        "u-1001", new User("u-1001", "Ana Martinez",  "ana@example.com",   "CC-1020304050", "+57 300 111 2233"),
        "u-2002", new User("u-2002", "Bruno Salcedo", "bruno@example.com", "CC-8070605040", "+57 301 444 5566")
    );

    public Optional<User> findById(String id) {
        return Optional.ofNullable(USERS.get(id));
    }
}
