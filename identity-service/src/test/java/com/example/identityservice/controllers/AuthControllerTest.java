package com.example.identityservice.controllers;

import com.example.identityservice.exceptions.TokenRefreshException;
import com.example.identityservice.models.dto.req.LoginReq;
import com.example.identityservice.models.dto.req.LogoutReq;
import com.example.identityservice.models.dto.req.RefreshTokenReq;
import com.example.identityservice.models.dto.res.JwtRes;
import com.example.identityservice.models.dto.res.TokenResponseDTO;
import com.example.identityservice.models.services.AuthService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.ObjectMapper;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuthController.class)
@AutoConfigureMockMvc(addFilters = false)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private AuthService authService;

    @Test
    @WithMockUser
    @DisplayName("POST /api/auth/login should return accessToken and refreshToken")
    void shouldReturnTokensOnLogin() throws Exception {
        LoginReq req = new LoginReq("testuser", "password123");
        JwtRes jwtRes = new JwtRes("access.token.123", "refresh.token.456", "Bearer", List.of("ROLE_USER"));

        when(authService.login(any(LoginReq.class))).thenReturn(jwtRes);

        mockMvc.perform(post("/api/auth/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("access.token.123"))
                .andExpect(jsonPath("$.refreshToken").value("refresh.token.456"))
                .andExpect(jsonPath("$.type").value("Bearer"))
                .andExpect(jsonPath("$.roles[0]").value("ROLE_USER"));
    }

    @Test
    @WithMockUser
    @DisplayName("POST /api/v1/auth/login should also work with versioned route")
    void shouldReturnTokensOnVersionedLoginRoute() throws Exception {
        LoginReq req = new LoginReq("testuser", "password123");
        JwtRes jwtRes = new JwtRes("access.token.123", "refresh.token.456", "Bearer", List.of("ROLE_USER"));

        when(authService.login(any(LoginReq.class))).thenReturn(jwtRes);

        mockMvc.perform(post("/api/v1/auth/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("access.token.123"))
                .andExpect(jsonPath("$.refreshToken").value("refresh.token.456"));
    }

    @Test
    @WithMockUser
    @DisplayName("POST /api/auth/login should return 400 Bad Request when validation fails")
    void shouldReturnBadRequestWhenLoginRequestInvalid() throws Exception {
        LoginReq invalidReq = new LoginReq("", "");

        mockMvc.perform(post("/api/auth/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidReq)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser
    @DisplayName("POST /api/auth/refresh should return new tokens on valid refresh request")
    void shouldReturnNewTokensOnRefresh() throws Exception {
        RefreshTokenReq req = new RefreshTokenReq("valid-refresh-token");
        TokenResponseDTO responseDTO = new TokenResponseDTO("new.access.token", "new-refresh-token", List.of("ROLE_USER"));

        when(authService.refreshToken(any(RefreshTokenReq.class))).thenReturn(responseDTO);

        mockMvc.perform(post("/api/auth/refresh")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("new.access.token"))
                .andExpect(jsonPath("$.refreshToken").value("new-refresh-token"))
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.type").value("Bearer"))
                .andExpect(jsonPath("$.roles[0]").value("ROLE_USER"));
    }

    @Test
    @WithMockUser
    @DisplayName("POST /api/v1/auth/refresh should also work with versioned route")
    void shouldReturnNewTokensOnVersionedRefreshRoute() throws Exception {
        RefreshTokenReq req = new RefreshTokenReq("valid-refresh-token");
        TokenResponseDTO responseDTO = new TokenResponseDTO("new.access.token", "new-refresh-token", List.of("ROLE_USER"));

        when(authService.refreshToken(any(RefreshTokenReq.class))).thenReturn(responseDTO);

        mockMvc.perform(post("/api/v1/auth/refresh")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("new.access.token"))
                .andExpect(jsonPath("$.refreshToken").value("new-refresh-token"));
    }

    @Test
    @WithMockUser
    @DisplayName("POST /api/auth/refresh should return 400 Bad Request when refreshToken is blank")
    void shouldReturnBadRequestWhenRefreshTokenBlank() throws Exception {
        RefreshTokenReq invalidReq = new RefreshTokenReq("");

        mockMvc.perform(post("/api/auth/refresh")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidReq)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser
    @DisplayName("POST /api/auth/refresh should return 403 Forbidden when token is invalid or expired")
    void shouldReturnForbiddenWhenTokenInvalidOrExpired() throws Exception {
        RefreshTokenReq req = new RefreshTokenReq("invalid-or-expired-token");

        when(authService.refreshToken(any(RefreshTokenReq.class)))
                .thenThrow(new TokenRefreshException("invalid-or-expired-token", "Refresh token was not found in database"));

        mockMvc.perform(post("/api/auth/refresh")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").exists());
    }

    @Test
    @WithMockUser
    @DisplayName("POST /api/auth/logout with Bearer header should return 200 OK")
    void shouldLogoutSuccessfullyWithBearerHeader() throws Exception {
        mockMvc.perform(post("/api/auth/logout")
                        .with(csrf())
                        .header("Authorization", "Bearer sample.access.token"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Logged out successfully"));
    }

    @Test
    @WithMockUser
    @DisplayName("POST /api/auth/logout with JSON request body should return 200 OK")
    void shouldLogoutSuccessfullyWithRequestBody() throws Exception {
        LogoutReq req = new LogoutReq("sample.access.token");

        mockMvc.perform(post("/api/auth/logout")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Logged out successfully"));
    }

    @Test
    @WithMockUser
    @DisplayName("POST /api/auth/logout without token should return 400 Bad Request")
    void shouldReturnBadRequestWhenNoTokenProvidedOnLogout() throws Exception {
        mockMvc.perform(post("/api/auth/logout")
                        .with(csrf()))
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser
    @DisplayName("POST /api/v1/auth/logout should also work with versioned route")
    void shouldLogoutSuccessfullyOnVersionedRoute() throws Exception {
        mockMvc.perform(post("/api/v1/auth/logout")
                        .with(csrf())
                        .header("Authorization", "Bearer sample.access.token"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Logged out successfully"));
    }
}
