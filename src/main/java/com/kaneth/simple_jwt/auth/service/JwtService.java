package com.kaneth.simple_jwt.auth.service;

import com.kaneth.simple_jwt.user.entity.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;

@Service
public class JwtService {

    @Value("${application.security.jwt.access-token.secret-key}")
    private String accessTokenSecretKey;
    @Value("${application.security.jwt.access-token.expiration}")
    private long accessTokenExpiration;

    @Value("${application.security.jwt.refresh-token.secret-key}")
    private String refreshTokenSecretKey;
    @Value("${application.security.jwt.refresh-token.expiration}")
    private long refreshTokenExpiration;

    public String generateAccessToken(final User user) {
        return buildToken(user, accessTokenSecretKey, accessTokenExpiration);
    }

    public String generateRefreshToken(final User user) {
        return buildToken(user, refreshTokenSecretKey, refreshTokenExpiration);
    }

    public String extractUsernameFromAccessToken(final String accessToken) {
        return Jwts.parser()
                .verifyWith(getSignInKey(accessTokenSecretKey))
                .build()
                .parseSignedClaims(accessToken)
                .getPayload()
                .getSubject();
    }

    public String extractUsernameFromRefreshToken(final String refreshToken) {
        return Jwts.parser()
                .verifyWith(getSignInKey(refreshTokenSecretKey))
                .build()
                .parseSignedClaims(refreshToken)
                .getPayload()
                .getSubject();
    }

    public boolean isAccessTokenValid(final String accessToken, final User user) {
        final String username = extractUsernameFromRefreshToken(accessToken);
        return username.equals(user.getUsername()) && !isTokenExpired(accessToken, accessTokenSecretKey);
    }

    public boolean isRefreshTokenValid(final String refreshToken, final User user) {
        final String username = extractUsernameFromRefreshToken(refreshToken);
        return username.equals(user.getUsername()) && !isTokenExpired(refreshToken, refreshTokenSecretKey);
    }

    private boolean isTokenExpired (final String token, final String secretKey) {
        return extractExpiration(token, secretKey).before(new Date());
    }

    private Date extractExpiration(final String token, final String secretKey) {
        return Jwts.parser()
                .verifyWith(getSignInKey(secretKey))
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getExpiration();
    }

    private String buildToken(final User user, final String secretKey, final long expiration) {
        return Jwts.builder()
                .subject(user.getUsername())
                //.claims() // agregar el rol aqui mas adelante
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey(secretKey))
                .compact();
    }

    private SecretKey getSignInKey(final String secretKey) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
