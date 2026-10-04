package com.example.identityservice.models.services;

import com.example.identityservice.exceptions.NotFoundException;
import com.example.identityservice.exceptions.TokenRefreshException;
import com.example.identityservice.models.entities.RefreshToken;
import com.example.identityservice.models.entities.User;
import com.example.identityservice.models.repositories.RefreshTokenRepository;
import com.example.identityservice.models.repositories.UserRepository;
import com.example.identityservice.models.services.impl.RefreshTokenServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private RefreshTokenServiceImpl refreshTokenService;

    private User sampleUser;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(refreshTokenService, "refreshTokenDurationMs", 604800000L); // 7 days
        sampleUser = User.builder()
                .id(1L)
                .username("testuser")
                .fullName("Test User")
                .build();
    }

    @Test
    @DisplayName("createRefreshToken should save and return RefreshToken for valid userId")
    void shouldCreateRefreshTokenSuccessfully() {
        when(userRepository.findById(1L)).thenReturn(Optional.of(sampleUser));
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(invocation -> {
            RefreshToken token = invocation.getArgument(0);
            token.setId(10L);
            return token;
        });

        RefreshToken createdToken = refreshTokenService.createRefreshToken(1L);

        assertNotNull(createdToken);
        assertEquals(10L, createdToken.getId());
        assertNotNull(createdToken.getToken());
        assertEquals(sampleUser, createdToken.getUser());
        assertTrue(createdToken.getExpiryDate().isAfter(Instant.now()));

        ArgumentCaptor<RefreshToken> captor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshTokenRepository).save(captor.capture());
        assertEquals(sampleUser, captor.getValue().getUser());
    }

    @Test
    @DisplayName("createRefreshToken should throw NotFoundException when user does not exist")
    void shouldThrowNotFoundExceptionWhenUserNotFound() {
        when(userRepository.findById(99L)).thenReturn(Optional.empty());

        assertThrows(NotFoundException.class, () -> refreshTokenService.createRefreshToken(99L));
        verify(refreshTokenRepository, never()).save(any());
    }

    @Test
    @DisplayName("verifyExpiration should return token if not expired")
    void shouldReturnTokenWhenNotExpired() {
        RefreshToken validToken = RefreshToken.builder()
                .id(1L)
                .token("valid-uuid")
                .user(sampleUser)
                .expiryDate(Instant.now().plus(1, ChronoUnit.HOURS))
                .build();

        RefreshToken result = refreshTokenService.verifyExpiration(validToken);

        assertNotNull(result);
        assertEquals("valid-uuid", result.getToken());
        verify(refreshTokenRepository, never()).delete(any());
    }

    @Test
    @DisplayName("verifyExpiration should delete token and throw TokenRefreshException when expired")
    void shouldDeleteAndThrowWhenTokenExpired() {
        RefreshToken expiredToken = RefreshToken.builder()
                .id(1L)
                .token("expired-uuid")
                .user(sampleUser)
                .expiryDate(Instant.now().minus(1, ChronoUnit.HOURS))
                .build();

        TokenRefreshException exception = assertThrows(
                TokenRefreshException.class,
                () -> refreshTokenService.verifyExpiration(expiredToken)
        );

        assertTrue(exception.getMessage().contains("expired"));
        verify(refreshTokenRepository).delete(expiredToken);
    }
}
