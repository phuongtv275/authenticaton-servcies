package com.example.identityservice.models.services;

import com.example.identityservice.exceptions.BadRequestException;
import com.example.identityservice.models.constants.RoleName;
import com.example.identityservice.models.dto.req.LoginReq;
import com.example.identityservice.models.dto.req.RefreshTokenReq;
import com.example.identityservice.models.dto.res.JwtRes;
import com.example.identityservice.models.dto.res.TokenResponseDTO;
import com.example.identityservice.models.entities.RefreshToken;
import com.example.identityservice.models.entities.Role;
import com.example.identityservice.models.entities.User;
import com.example.identityservice.models.services.impl.AuthServiceImpl;
import com.example.identityservice.security.jwt.JwtUtils;
import com.example.identityservice.security.principal.MyUserDetails;
import com.example.identityservice.models.repositories.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private JwtUtils jwtUtils;

    @Mock
    private RefreshTokenService refreshTokenService;

    @Mock
    private RedisBlacklistService redisBlacklistService;

    @Mock
    private UserRepository userRepository;

    @Mock
    private Authentication authentication;

    @InjectMocks
    private AuthServiceImpl authService;

    private User sampleUser;
    private MyUserDetails userDetails;

    @BeforeEach
    void setUp() {
        Role role = Role.builder().id(1L).roleName(RoleName.ROLE_USER).build();
        sampleUser = User.builder()
                .id(1L)
                .username("testuser")
                .password("encoded_pass")
                .fullName("Test User")
                .roles(Set.of(role))
                .build();
        userDetails = MyUserDetails.builder()
                .user(sampleUser)
                .authorities(java.util.List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_USER")))
                .build();
    }

    @Test
    @DisplayName("login should return both accessToken and refreshToken on valid credentials")
    void shouldReturnAccessAndRefreshTokenOnSuccessfulLogin() {
        LoginReq req = new LoginReq("testuser", "password123");

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(userDetails);
        when(jwtUtils.generateAccessToken(sampleUser)).thenReturn("sample.access.token");

        RefreshToken sampleRefreshToken = RefreshToken.builder()
                .id(100L)
                .token("sample-refresh-uuid")
                .expiryDate(Instant.now().plusSeconds(604800))
                .user(sampleUser)
                .build();
        when(refreshTokenService.createRefreshToken(sampleUser)).thenReturn(sampleRefreshToken);

        JwtRes res = authService.login(req);

        assertNotNull(res);
        assertEquals("sample.access.token", res.accessToken());
        assertEquals("sample-refresh-uuid", res.refreshToken());
        assertEquals("Bearer", res.type());
        assertTrue(res.roles().contains("ROLE_USER"));

        verify(jwtUtils).generateAccessToken(sampleUser);
        verify(refreshTokenService).createRefreshToken(sampleUser);
    }

    @Test
    @DisplayName("login should throw BadRequestException on bad credentials")
    void shouldThrowBadRequestExceptionOnBadCredentials() {
        LoginReq req = new LoginReq("wrong_user", "wrong_pass");
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("Bad credentials"));

        assertThrows(BadRequestException.class, () -> authService.login(req));
        verify(jwtUtils, never()).generateAccessToken(any());
        verify(refreshTokenService, never()).createRefreshToken(any(User.class));
        verify(refreshTokenService, never()).createRefreshToken(any(Long.class));
    }

    @Test
    @DisplayName("refreshToken should delegate to refreshTokenService")
    void shouldDelegateRefreshTokenToService() {
        RefreshTokenReq req = new RefreshTokenReq("sample-refresh-uuid");
        TokenResponseDTO expectedRes = new TokenResponseDTO("new.access.token", "new-refresh-uuid", java.util.List.of("ROLE_USER"));
        when(refreshTokenService.refreshToken("sample-refresh-uuid")).thenReturn(expectedRes);

        TokenResponseDTO actualRes = authService.refreshToken(req);

        assertNotNull(actualRes);
        assertEquals("new.access.token", actualRes.accessToken());
        assertEquals("new-refresh-uuid", actualRes.refreshToken());
        verify(refreshTokenService).refreshToken("sample-refresh-uuid");
    }

    @Test
    @DisplayName("logout should blacklist token and delete user refresh tokens in database")
    void shouldLogoutSuccessfully() {
        String token = "Bearer valid.access.token";
        io.jsonwebtoken.Claims mockClaims = mock(io.jsonwebtoken.Claims.class);
        when(mockClaims.getSubject()).thenReturn("testuser");
        when(redisBlacklistService.blacklistToken("valid.access.token")).thenReturn(mockClaims);
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(sampleUser));

        authService.logout(token);

        verify(redisBlacklistService).blacklistToken("valid.access.token");
        verify(refreshTokenService).deleteByUser(sampleUser);
    }

    @Test
    @DisplayName("logout should throw BadRequestException when token is blank")
    void shouldThrowBadRequestExceptionWhenTokenIsBlank() {
        assertThrows(BadRequestException.class, () -> authService.logout(""));
        assertThrows(BadRequestException.class, () -> authService.logout(null));
        verify(redisBlacklistService, never()).blacklistToken(any());
    }
}
