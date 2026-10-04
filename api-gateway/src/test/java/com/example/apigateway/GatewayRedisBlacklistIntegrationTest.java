package com.example.apigateway;

import com.example.apigateway.filter.JwtAuthFilter;
import com.example.apigateway.security.JwtUtils;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import javax.crypto.SecretKey;
import java.time.Duration;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class GatewayRedisBlacklistIntegrationTest {

    @Autowired
    private JwtAuthFilter jwtAuthFilter;

    @Autowired
    private ReactiveStringRedisTemplate redisTemplate;

    @Value("${jwt.secret-key}")
    private String secretKey;

    private SecretKey signingKey;
    private String testJti;
    private String testToken;

    @BeforeEach
    void setUp() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        signingKey = Keys.hmacShaKeyFor(keyBytes);

        testJti = UUID.randomUUID().toString();
        testToken = Jwts.builder()
                .subject("gateway_user")
                .id(testJti)
                .claim("roles", List.of("ROLE_USER"))
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 900000))
                .signWith(signingKey)
                .compact();
    }

    @AfterEach
    void tearDown() {
        if (testJti != null) {
            redisTemplate.delete(JwtAuthFilter.BLACKLIST_KEY_PREFIX + testJti).block();
        }
    }

    @Test
    @DisplayName("Filter should allow valid token when not blacklisted, and reject with 401 when blacklisted in Redis")
    void shouldBlockBlacklistedTokenLiveInRedis() {
        String redisKey = JwtAuthFilter.BLACKLIST_KEY_PREFIX + testJti;

        // 1. Trước khi Blacklist: Key chưa có trong Redis
        Boolean keyExistsBefore = redisTemplate.hasKey(redisKey).block();
        assertFalse(Boolean.TRUE.equals(keyExistsBefore), "Key must not exist in Redis before blacklist");

        AtomicBoolean chainCalled = new AtomicBoolean(false);
        WebFilterChain chain = exchange -> {
            chainCalled.set(true);
            return Mono.empty();
        };

        MockServerHttpRequest req1 = MockServerHttpRequest.get("/product/api/products")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + testToken)
                .build();
        MockServerWebExchange exchange1 = MockServerWebExchange.from(req1);

        StepVerifier.create(jwtAuthFilter.filter(exchange1, chain))
                .verifyComplete();

        assertTrue(chainCalled.get(), "Chain must be invoked when token is valid and not blacklisted");
        assertNull(exchange1.getResponse().getStatusCode(), "Status code should not be set to error on pass");

        // 2. Đưa token vào Blacklist trong Redis (mô phỏng hành động Logout)
        Boolean stored = redisTemplate.opsForValue().set(redisKey, "revoked", Duration.ofMinutes(15)).block();
        assertTrue(Boolean.TRUE.equals(stored), "Redis set must succeed");

        Boolean keyExistsAfter = redisTemplate.hasKey(redisKey).block();
        assertTrue(Boolean.TRUE.equals(keyExistsAfter), "Key must exist in Redis after blacklist");

        // 3. Gửi lại request với chính token đó: Gateway phải chặn lại ngay lập tức
        chainCalled.set(false);
        MockServerHttpRequest req2 = MockServerHttpRequest.get("/product/api/products")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + testToken)
                .build();
        MockServerWebExchange exchange2 = MockServerWebExchange.from(req2);

        StepVerifier.create(jwtAuthFilter.filter(exchange2, chain))
                .verifyComplete();

        assertFalse(chainCalled.get(), "Chain must NOT be invoked when token is blacklisted");
        assertEquals(HttpStatus.UNAUTHORIZED, exchange2.getResponse().getStatusCode(), "Response must be 401 Unauthorized");
    }
}
