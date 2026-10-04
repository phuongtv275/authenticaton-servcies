package com.example.identityservice.models.services;

import com.example.identityservice.exceptions.BadRequestException;
import com.example.identityservice.models.services.impl.RedisBlacklistServiceImpl;
import com.example.identityservice.security.jwt.JwtUtils;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.util.Date;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RedisBlacklistServiceTest {

    @Mock
    private StringRedisTemplate redisTemplate;

    @Mock
    private ValueOperations<String, String> valueOperations;

    @Mock
    private JwtUtils jwtUtils;

    @Mock
    private Claims claims;

    @InjectMocks
    private RedisBlacklistServiceImpl redisBlacklistService;

    @Test
    @DisplayName("blacklistToken should save key with prefix blacklist: and TTL to Redis")
    void shouldBlacklistTokenSuccessfully() {
        String token = "valid.jwt.token";
        String jti = "test-jti-uuid";
        long futureTime = System.currentTimeMillis() + 60000; // 60s in future
        Date exp = new Date(futureTime);

        when(jwtUtils.extractAllClaims(token)).thenReturn(claims);
        when(claims.getId()).thenReturn(jti);
        when(claims.getExpiration()).thenReturn(exp);
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);

        redisBlacklistService.blacklistToken(token);

        verify(valueOperations).set(
                eq("blacklist:" + jti),
                eq("revoked"),
                longThat(ttl -> ttl > 0 && ttl <= 60000),
                eq(TimeUnit.MILLISECONDS)
        );
    }

    @Test
    @DisplayName("blacklistToken should throw BadRequestException when jti is missing")
    void shouldThrowBadRequestExceptionWhenJtiMissing() {
        String token = "token.without.jti";
        when(jwtUtils.extractAllClaims(token)).thenReturn(claims);
        when(claims.getId()).thenReturn(null);

        assertThrows(BadRequestException.class, () -> redisBlacklistService.blacklistToken(token));
        verify(redisTemplate, never()).opsForValue();
    }

    @Test
    @DisplayName("isBlacklisted should return true if key exists in Redis")
    void shouldReturnTrueWhenKeyExistsInRedis() {
        when(redisTemplate.hasKey("blacklist:revoked-jti")).thenReturn(true);

        assertTrue(redisBlacklistService.isBlacklisted("revoked-jti"));
        verify(redisTemplate).hasKey("blacklist:revoked-jti");
    }

    @Test
    @DisplayName("isBlacklisted should return false if key does not exist or jti is null")
    void shouldReturnFalseWhenKeyDoesNotExistOrNull() {
        when(redisTemplate.hasKey("blacklist:active-jti")).thenReturn(false);

        assertFalse(redisBlacklistService.isBlacklisted("active-jti"));
        assertFalse(redisBlacklistService.isBlacklisted(null));
        assertFalse(redisBlacklistService.isBlacklisted(""));
    }
}
