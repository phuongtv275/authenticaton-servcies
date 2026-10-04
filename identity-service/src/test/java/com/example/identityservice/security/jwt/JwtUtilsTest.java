package com.example.identityservice.security.jwt;

import com.example.identityservice.models.constants.RoleName;
import com.example.identityservice.models.entities.Role;
import com.example.identityservice.models.entities.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.Key;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class JwtUtilsTest {

    private JwtUtils jwtUtils;

    @BeforeEach
    void setUp() {
        jwtUtils = new JwtUtils();
        ReflectionTestUtils.setField(jwtUtils, "secretKey", "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970");
        ReflectionTestUtils.setField(jwtUtils, "accessTokenExpiration", 900000L);
    }

    @Test
    @DisplayName("generateAccessToken should create a valid JWT with user claims and expiration")
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

        Key signKey = jwtUtils.getSignKey();
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(signKey)
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
}
