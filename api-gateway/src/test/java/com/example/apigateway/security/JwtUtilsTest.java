package com.example.apigateway.security;

import com.example.apigateway.config.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class JwtUtilsTest {

    private static final String VALID_BASE64_SECRET = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";
    private JwtUtils jwtUtils;
    private SecretKey signingKey;

    @BeforeEach
    void setUp() {
        JwtProperties jwtProperties = new JwtProperties();
        jwtProperties.setSecretKey(VALID_BASE64_SECRET);
        jwtProperties.setWhitelistPaths(List.of("/identity/api/v1/auth/**"));

        jwtUtils = new JwtUtils(jwtProperties);

        byte[] keyBytes = Decoders.BASE64.decode(VALID_BASE64_SECRET);
        signingKey = Keys.hmacShaKeyFor(keyBytes);
    }

    private String buildToken(String username, String jti, long expirationOffsetMs) {
        var builder = Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expirationOffsetMs))
                .signWith(signingKey);

        if (jti != null) {
            builder.id(jti);
        }
        return builder.compact();
    }

    @Test
    @DisplayName("extractJti should extract valid jti claim from signed JWT")
    void shouldExtractJtiFromValidToken() {
        String expectedJti = UUID.randomUUID().toString();
        String token = buildToken("test_user", expectedJti, 60000);

        String actualJti = jwtUtils.extractJti(token);

        assertEquals(expectedJti, actualJti);
    }

    @Test
    @DisplayName("extractJti should return null when token does not contain jti claim")
    void shouldReturnNullWhenTokenHasNoJti() {
        String token = buildToken("test_user", null, 60000);

        String actualJti = jwtUtils.extractJti(token);

        assertNull(actualJti);
    }

    @Test
    @DisplayName("parseToken should throw ExpiredJwtException when token is expired")
    void shouldThrowExpiredJwtExceptionWhenTokenExpired() {
        String expiredToken = buildToken("test_user", "jti-123", -10000);

        assertThrows(ExpiredJwtException.class, () -> jwtUtils.parseToken(expiredToken));
    }

    @Test
    @DisplayName("parseToken should throw JwtException when token is malformed or signature is invalid")
    void shouldThrowJwtExceptionWhenTokenMalformed() {
        assertThrows(JwtException.class, () -> jwtUtils.parseToken("invalid.jwt.token"));
    }

    @Test
    @DisplayName("isTokenValid should return true for valid token and false for invalid/expired token")
    void shouldValidateTokenCorrectly() {
        String validToken = buildToken("test_user", "jti-123", 60000);
        String expiredToken = buildToken("test_user", "jti-123", -10000);

        assertTrue(jwtUtils.isTokenValid(validToken));
        assertFalse(jwtUtils.isTokenValid(expiredToken));
        assertFalse(jwtUtils.isTokenValid("malformed.token"));
    }
}
