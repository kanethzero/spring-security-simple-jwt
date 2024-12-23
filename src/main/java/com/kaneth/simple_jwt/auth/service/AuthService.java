package com.kaneth.simple_jwt.auth.service;

import com.kaneth.simple_jwt.auth.dto.LoginRequest;
import com.kaneth.simple_jwt.auth.dto.RegisterRequest;
import com.kaneth.simple_jwt.auth.dto.TokenResponse;
import com.kaneth.simple_jwt.auth.entity.Token;
import com.kaneth.simple_jwt.auth.repository.TokenRepository;
import com.kaneth.simple_jwt.user.entity.User;
import com.kaneth.simple_jwt.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public TokenResponse register(RegisterRequest request) {
        var user = User.builder()
                .name(request.name())
                .email(request.email())
                .username(request.username())
                .password(passwordEncoder.encode(request.password()))
                .build();
        var savedUser = userRepository.save(user);
        var accessToken = jwtService.generateAccessToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        saveUserToken(savedUser, accessToken);
        return new TokenResponse(accessToken, refreshToken);
    }

    public TokenResponse login (LoginRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.username(),
                        request.password()
                )
        );
        final User user = userRepository.findByUsername(request.username())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, accessToken);
        return new TokenResponse(accessToken, refreshToken);
    }

    public TokenResponse refreshToken(final String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new IllegalArgumentException("Invalid Bearer Token");
        }

        final String refreshToken = authHeader.substring(7);
        final String username = jwtService.extractUsernameFromRefreshToken(refreshToken);

        if(username == null) {
            throw new IllegalArgumentException("Invalid Refresh Token");
        }

        final User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User '" + username + "' not found"));

        if(!jwtService.isRefreshTokenValid(refreshToken, user)) {
            throw new IllegalArgumentException("Invalid Refresh Token");
        }

        final String accessToken = jwtService.generateAccessToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, accessToken);
        return new TokenResponse(accessToken, refreshToken);
    }

    private void saveUserToken(User user, String token) {
        var savedToken = Token.builder()
                .user(user)
                .token(token)
                .tokenType(Token.TokenType.BEARER)
                .build();
        tokenRepository.save(savedToken);
    }

    private void revokeAllUserTokens(final User user) {
        final List<Token> validUserTokens = tokenRepository.findValidTokensByUserId(user.getUserId());
        if(!validUserTokens.isEmpty()) {
            for (Token token : validUserTokens) {
                token.setRevoked(true);
                token.setExpired(true);
            }
            tokenRepository.saveAll(validUserTokens);
        }
    }

}
