package com.example.identityservice;

import com.example.identityservice.exceptions.TokenRefreshException;
import com.example.identityservice.models.constants.RoleName;
import com.example.identityservice.models.dto.res.TokenResponseDTO;
import com.example.identityservice.models.entities.RefreshToken;
import com.example.identityservice.models.entities.Role;
import com.example.identityservice.models.entities.User;
import com.example.identityservice.models.repositories.RefreshTokenRepository;
import com.example.identityservice.models.repositories.RoleRepository;
import com.example.identityservice.models.repositories.UserRepository;
import com.example.identityservice.models.services.RefreshTokenService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class TokenRotationIntegrationTest {

    @Autowired
    private RefreshTokenService refreshTokenService;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    private User testUser;

    @BeforeEach
    void setUp() {
        Role role = roleRepository.findByRoleName(RoleName.ROLE_USER)
                .orElseGet(() -> roleRepository.save(Role.builder().roleName(RoleName.ROLE_USER).build()));

        String username = "rotation_test_" + UUID.randomUUID().toString().substring(0, 8);
        testUser = userRepository.save(User.builder()
                .username(username)
                .password("secret123")
                .fullName("Rotation Tester")
                .roles(new HashSet<>(Set.of(role)))
                .build());
    }

    @AfterEach
    void tearDown() {
        if (testUser != null && testUser.getId() != null) {
            refreshTokenRepository.deleteByUser(testUser);
            userRepository.delete(testUser);
        }
    }

    @Test
    @DisplayName("Complete Token Rotation lifecycle test against real DB")
    void testTokenRotationLifecycle() {
        // Step 1: Login creates RefreshToken R1
        RefreshToken r1 = refreshTokenService.createRefreshToken(testUser);
        assertNotNull(r1);
        String r1Token = r1.getToken();
        assertTrue(refreshTokenRepository.findByToken(r1Token).isPresent());

        // Step 2: Call refreshToken(R1) -> should yield Access Token B and Refresh Token R2
        TokenResponseDTO response1 = refreshTokenService.refreshToken(r1Token);
        assertNotNull(response1);
        assertNotNull(response1.accessToken());
        assertNotNull(response1.refreshToken());
        assertNotEquals(r1Token, response1.refreshToken());

        String r2Token = response1.refreshToken();

        // Check DB: R1 must be deleted, R2 must exist
        assertFalse(refreshTokenRepository.findByToken(r1Token).isPresent(), "R1 must be deleted from DB");
        Optional<RefreshToken> r2InDb = refreshTokenRepository.findByToken(r2Token);
        assertTrue(r2InDb.isPresent(), "R2 must be present in DB");
        assertEquals(testUser.getId(), r2InDb.get().getUser().getId());

        // Step 3: Call refreshToken(R1) AGAIN -> Expect TokenRefreshException (mapped to 403 Forbidden)
        assertThrows(TokenRefreshException.class, () -> refreshTokenService.refreshToken(r1Token),
                "Using deleted R1 must throw TokenRefreshException (403 Forbidden)");

        // Step 4: Call refreshToken(R2) -> should yield Access Token C and Refresh Token R3
        TokenResponseDTO response2 = refreshTokenService.refreshToken(r2Token);
        assertNotNull(response2);
        assertNotNull(response2.accessToken());
        assertNotNull(response2.refreshToken());
        assertNotEquals(r2Token, response2.refreshToken());

        String r3Token = response2.refreshToken();
        assertFalse(refreshTokenRepository.findByToken(r2Token).isPresent(), "R2 must be deleted from DB");
        assertTrue(refreshTokenRepository.findByToken(r3Token).isPresent(), "R3 must be present in DB");
    }

    @Test
    @DisplayName("Expired token must be physically deleted from DB and reject with TokenRefreshException")
    void testExpiredTokenIsDeletedFromDatabaseOnRefresh() {
        // Tạo token đã hết hạn 1 giờ trước
        RefreshToken expiredToken = refreshTokenRepository.save(RefreshToken.builder()
                .user(testUser)
                .token("expired-" + UUID.randomUUID())
                .expiryDate(Instant.now().minus(1, ChronoUnit.HOURS))
                .build());

        String expiredTokenString = expiredToken.getToken();
        assertTrue(refreshTokenRepository.findByToken(expiredTokenString).isPresent());

        // Gọi refreshToken -> ném TokenRefreshException
        assertThrows(TokenRefreshException.class, () -> refreshTokenService.refreshToken(expiredTokenString));

        // Xác nhận bản ghi token hết hạn thực sự đã bị xóa khỏi DB (commit thành công nhờ noRollbackFor)
        assertFalse(refreshTokenRepository.findByToken(expiredTokenString).isPresent(),
                "Expired token must be committed deleted from DB even when TokenRefreshException is thrown");
    }

    @Test
    @DisplayName("Concurrent refresh requests with the same token: exactly one must succeed")
    void testConcurrentRefreshRequestsWithSameToken() throws Exception {
        RefreshToken r1 = refreshTokenService.createRefreshToken(testUser);
        String tokenString = r1.getToken();

        int threadCount = 2;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch endLatch = new CountDownLatch(threadCount);

        AtomicInteger successCount = new AtomicInteger(0);
        AtomicInteger failureCount = new AtomicInteger(0);

        for (int i = 0; i < threadCount; i++) {
            executor.submit(() -> {
                try {
                    startLatch.await();
                    refreshTokenService.refreshToken(tokenString);
                    successCount.incrementAndGet();
                } catch (TokenRefreshException e) {
                    failureCount.incrementAndGet();
                } catch (Exception e) {
                    // unexpected error
                } finally {
                    endLatch.countDown();
                }
            });
        }

        // Bắt đầu 2 thread cùng lúc
        startLatch.countDown();
        assertTrue(endLatch.await(5, TimeUnit.SECONDS));
        executor.shutdown();

        assertEquals(1, successCount.get(), "Exactly one concurrent refresh request must succeed");
        assertEquals(1, failureCount.get(), "The other concurrent refresh request must receive 403 / TokenRefreshException");
    }
}
