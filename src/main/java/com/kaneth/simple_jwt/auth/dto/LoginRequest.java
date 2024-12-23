package com.kaneth.simple_jwt.auth.dto;

public record LoginRequest(
        String username,
        String password
) {
}
