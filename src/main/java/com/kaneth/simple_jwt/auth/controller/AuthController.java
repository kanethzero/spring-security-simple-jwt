package com.kaneth.simple_jwt.auth.controller;

import com.kaneth.simple_jwt.auth.dto.LoginRequest;
import com.kaneth.simple_jwt.auth.dto.RegisterRequest;
import com.kaneth.simple_jwt.auth.dto.TokenResponse;
import com.kaneth.simple_jwt.auth.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<TokenResponse> register(@RequestBody final RegisterRequest registerRequest) {
        final TokenResponse tokenResponse = authService.register(registerRequest);
        return ResponseEntity.ok(tokenResponse);
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@RequestBody final LoginRequest loginRequest) {
        final TokenResponse tokenResponse = authService.login(loginRequest);
        return ResponseEntity.ok(tokenResponse);
    }

    @PostMapping("/refresh-token")
    public TokenResponse refreshToken(@RequestHeader(HttpHeaders.AUTHORIZATION) final String authHeader) {
        return authService.refreshToken(authHeader);
    }

}
