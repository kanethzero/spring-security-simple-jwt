package com.kaneth.simple_jwt.auth.dto;

public record RegisterRequest(
        String name,
        String email,
        String username,
        String password
) {
}
