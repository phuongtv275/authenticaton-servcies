package com.example.identityservice.security.jwt;

import com.example.identityservice.models.constants.RoleName;
import com.example.identityservice.models.entities.Role;
import com.example.identityservice.models.entities.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.Key;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class JwtUtilsTest {

    private static final String VALID_BASE64_SECRET = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";
    private JwtUtils jwtUtils;

    @BeforeEach
    void setUp() {
        jwtUtils = new JwtUtils();
        ReflectionTestUtils.setField(jwtUtils, "secretKey", VALID_BASE64_SECRET);
        ReflectionTestUtils.setField(jwtUtils, "accessTokenExpiration", 900000L);
        jwtUtils.init();
    }

    @Test
    @DisplayName("generateAccessToken should create a valid JWT verified with Base64 decoded key like Gateway")
    void shouldGenerateAccessTokenSuccessfully() {
        Role role = Role.builder().id(1L).roleName(RoleName.ROLE_USER).build();
        User user = User.builder()
                .id(1L)
                .username("john_doe")
                .fullName("John Doe")
                .roles(Set.of(role))
                .build();

        String token = jwtUtils.generateAccessToken(user);

        assertNotNull(token);
        assertFalse(token.isBlank());

        // Verify using independent Base64 key decoding (matching Gateway's logic)
        Key gatewayVerificationKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(VALID_BASE64_SECRET));
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(gatewayVerificationKey)
                .build()
                .parseClaimsJws(token)
                .getBody();

        assertEquals("john_doe", claims.getSubject());
        assertEquals("john_doe", claims.get("username"));
        @SuppressWarnings("unchecked")
        List<String> roles = (List<String>) claims.get("roles");
        assertNotNull(roles);
        assertTrue(roles.contains("ROLE_USER"));
        assertNotNull(claims.getExpiration());
        assertTrue(claims.getExpiration().getTime() > System.currentTimeMillis());
    }

    @Test
    @DisplayName("init should fail fast on startup if secret is not valid Base64")
    void shouldFailFastWhenSecretIsNotBase64() {
        JwtUtils badJwtUtils = new JwtUtils();
        ReflectionTestUtils.setField(badJwtUtils, "secretKey", "invalid_base64_secret_!@#$%");

        assertThrows(io.jsonwebtoken.io.DecodingException.class, badJwtUtils::init);
    }
}
