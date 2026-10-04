package com.example.identityservice.models.services;

import com.example.identityservice.exceptions.BadRequestException;
import com.example.identityservice.models.constants.RoleName;
import com.example.identityservice.models.dto.req.LoginReq;
import com.example.identityservice.models.dto.res.JwtRes;
import com.example.identityservice.models.entities.RefreshToken;
import com.example.identityservice.models.entities.Role;
import com.example.identityservice.models.entities.User;
import com.example.identityservice.models.services.impl.AuthServiceImpl;
import com.example.identityservice.security.jwt.JwtUtils;
import com.example.identityservice.security.principal.MyUserDetails;
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
        when(refreshTokenService.createRefreshToken(1L)).thenReturn(sampleRefreshToken);

        JwtRes res = authService.login(req);

        assertNotNull(res);
        assertEquals("sample.access.token", res.accessToken());
        assertEquals("sample-refresh-uuid", res.refreshToken());
        assertEquals("Bearer", res.type());
        assertTrue(res.roles().contains("ROLE_USER"));

        verify(jwtUtils).generateAccessToken(sampleUser);
        verify(refreshTokenService).createRefreshToken(1L);
    }

    @Test
    @DisplayName("login should throw BadRequestException on bad credentials")
    void shouldThrowBadRequestExceptionOnBadCredentials() {
        LoginReq req = new LoginReq("wrong_user", "wrong_pass");
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("Bad credentials"));

        assertThrows(BadRequestException.class, () -> authService.login(req));
        verify(jwtUtils, never()).generateAccessToken(any());
        verify(refreshTokenService, never()).createRefreshToken(any());
    }
}
