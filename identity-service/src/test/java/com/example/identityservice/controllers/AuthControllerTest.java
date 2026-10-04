package com.example.identityservice.controllers;

import com.example.identityservice.models.dto.req.LoginReq;
import com.example.identityservice.models.dto.res.JwtRes;
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
}
