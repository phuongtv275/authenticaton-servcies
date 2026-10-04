package com.example.identityservice;

import com.example.identityservice.models.constants.RoleName;
import com.example.identityservice.models.entities.RefreshToken;
import com.example.identityservice.models.entities.Role;
import com.example.identityservice.models.entities.User;
import com.example.identityservice.models.repositories.RefreshTokenRepository;
import com.example.identityservice.models.repositories.RoleRepository;
import com.example.identityservice.models.repositories.UserRepository;
import com.example.identityservice.models.services.AuthService;
import com.example.identityservice.models.services.RedisBlacklistService;
import com.example.identityservice.models.services.RefreshTokenService;
import com.example.identityservice.security.jwt.JwtUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class LogoutRedisIntegrationTest {

    @Autowired
    private AuthService authService;

    @Autowired
    private RedisBlacklistService redisBlacklistService;

    @Autowired
    private RefreshTokenService refreshTokenService;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private StringRedisTemplate redisTemplate;

    private User testUser;
    private String createdJti;

    @BeforeEach
    void setUp() {
        Role role = roleRepository.findByRoleName(RoleName.ROLE_USER)
                .orElseGet(() -> roleRepository.save(Role.builder().roleName(RoleName.ROLE_USER).build()));

        String username = "logout_test_" + UUID.randomUUID().toString().substring(0, 8);
        testUser = userRepository.save(User.builder()
                .username(username)
                .password("password123")
                .fullName("Logout Tester")
                .roles(new HashSet<>(Set.of(role)))
                .build());
    }

    @AfterEach
    void tearDown() {
        if (createdJti != null) {
            redisTemplate.delete("blacklist:" + createdJti);
        }
        if (testUser != null && testUser.getId() != null) {
            refreshTokenRepository.deleteByUser(testUser);
            userRepository.delete(testUser);
        }
    }

    @Test
    @DisplayName("Logout should write blacklist key to Redis with TTL and revoke refresh token in DB")
    void testLogoutAndBlacklistInRedis() {
        // 1. Cấp Access Token và Refresh Token cho User
        String accessToken = jwtUtils.generateAccessToken(testUser);
        createdJti = jwtUtils.extractJti(accessToken);
        assertNotNull(createdJti, "Access token must contain a valid jti");

        RefreshToken refreshToken = refreshTokenService.createRefreshToken(testUser);
        assertTrue(refreshTokenRepository.findByToken(refreshToken.getToken()).isPresent(),
                "Refresh token must be present before logout");

        // Trước khi logout, token chưa bị blacklist
        assertFalse(redisBlacklistService.isBlacklisted(createdJti));
        assertFalse(Boolean.TRUE.equals(redisTemplate.hasKey("blacklist:" + createdJti)));

        // 2. Thực hiện Logout
        authService.logout(accessToken);

        // 3. Kiểm tra Redis: Key blacklist:<jti> phải tồn tại với giá trị "revoked"
        String redisKey = "blacklist:" + createdJti;
        assertTrue(Boolean.TRUE.equals(redisTemplate.hasKey(redisKey)), "Key blacklist:<jti> must exist in Redis");
        assertEquals("revoked", redisTemplate.opsForValue().get(redisKey));

        // 4. Kiểm tra TTL trong Redis: phải > 0 và <= 900 giây (15 phút)
        Long ttlSeconds = redisTemplate.getExpire(redisKey, TimeUnit.SECONDS);
        assertNotNull(ttlSeconds);
        assertTrue(ttlSeconds > 0, "TTL must be greater than 0");
        assertTrue(ttlSeconds <= 900, "TTL must match remaining token validity (<= 900s)");

        // 5. Kiểm tra qua service isBlacklisted
        assertTrue(redisBlacklistService.isBlacklisted(createdJti));

        // 6. Kiểm tra PostgreSQL: Refresh Token của user đã bị xóa
        assertFalse(refreshTokenRepository.findByToken(refreshToken.getToken()).isPresent(),
                "User refresh token must be revoked from PostgreSQL on logout");
    }

    @Test
    @DisplayName("Logout with expired access token should revoke refresh token in Postgres and skip Redis storage")
    void testLogoutWithExpiredAccessTokenRevokesRefreshTokenInPostgres() {
        // 1. Sinh token đã hết hạn cho testUser
        String expiredJti = UUID.randomUUID().toString();
        java.util.Map<String, Object> claims = new java.util.HashMap<>();
        claims.put("username", testUser.getUsername());
        claims.put(io.jsonwebtoken.Claims.ID, expiredJti);

        String expiredToken = io.jsonwebtoken.Jwts.builder()
                .setClaims(claims)
                .setSubject(testUser.getUsername())
                .setIssuedAt(new java.util.Date(System.currentTimeMillis() - 100000))
                .setExpiration(new java.util.Date(System.currentTimeMillis() - 50000))
                .signWith((java.security.Key) org.springframework.test.util.ReflectionTestUtils.getField(jwtUtils, "signKey"), io.jsonwebtoken.SignatureAlgorithm.HS256)
                .compact();

        RefreshToken refreshToken = refreshTokenService.createRefreshToken(testUser);
        assertTrue(refreshTokenRepository.findByToken(refreshToken.getToken()).isPresent(),
                "Refresh token must be present before logout");

        // 2. Thực hiện logout với token đã hết hạn
        assertDoesNotThrow(() -> authService.logout(expiredToken));

        // 3. Redis: Không lưu key vì token đã hết hạn (TTL <= 0)
        String redisKey = "blacklist:" + expiredJti;
        assertFalse(Boolean.TRUE.equals(redisTemplate.hasKey(redisKey)), "Expired token should not be stored in Redis");

        // 4. PostgreSQL: Refresh Token của user vẫn phải được thu hồi/xóa
        assertFalse(refreshTokenRepository.findByToken(refreshToken.getToken()).isPresent(),
                "User refresh token must still be revoked in PostgreSQL even if access token is expired");
    }
}
