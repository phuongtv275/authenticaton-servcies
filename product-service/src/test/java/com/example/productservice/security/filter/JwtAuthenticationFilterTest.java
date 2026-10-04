package com.example.productservice.security.filter;

import com.example.productservice.security.jwt.JwtTokenValidator;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationFilterTest {

    @Mock
    private JwtTokenValidator jwtTokenValidator;

    @Mock
    private FilterChain filterChain;

    @InjectMocks
    private JwtAuthenticationFilter filter;

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("should authenticate user and set ROLE_ authorities when valid Bearer token provided")
    void shouldAuthenticateValidBearerToken() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(JwtAuthenticationFilter.AUTHORIZATION_HEADER, "Bearer valid-jwt-token");
        MockHttpServletResponse response = new MockHttpServletResponse();

        when(jwtTokenValidator.validateToken("valid-jwt-token")).thenReturn(true);
        when(jwtTokenValidator.getUsername("valid-jwt-token")).thenReturn("admin_user");
        when(jwtTokenValidator.getRoles("valid-jwt-token")).thenReturn(List.of("ROLE_ADMIN", "USER"));

        filter.doFilterInternal(request, response, filterChain);

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        assertNotNull(auth);
        assertEquals("admin_user", auth.getName());
        assertTrue(auth.isAuthenticated());

        List<String> authorities = auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        assertTrue(authorities.contains("ROLE_ADMIN"));
        assertTrue(authorities.contains("ROLE_USER"));
        assertTrue(authorities.contains("USER"));

        verify(filterChain).doFilter(request, response);
    }

    @Test
    @DisplayName("should skip authentication when header is missing or does not start with Bearer")
    void shouldSkipAuthenticationWhenHeaderMissing() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(jwtTokenValidator);
    }

    @Test
    @DisplayName("should not set authentication when token is invalid")
    void shouldNotAuthenticateWhenTokenInvalid() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(JwtAuthenticationFilter.AUTHORIZATION_HEADER, "Bearer invalid-jwt");
        MockHttpServletResponse response = new MockHttpServletResponse();

        when(jwtTokenValidator.validateToken("invalid-jwt")).thenReturn(false);

        filter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(filterChain).doFilter(request, response);
    }
}
