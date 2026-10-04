package com.example.identityservice.controllers;

import com.example.identityservice.models.dto.req.LoginReq;
import com.example.identityservice.models.dto.req.RefreshTokenReq;
import com.example.identityservice.models.dto.req.RegisterReq;
import com.example.identityservice.models.dto.res.JwtRes;
import com.example.identityservice.models.dto.res.TokenResponseDTO;
import com.example.identityservice.models.services.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping({"/api/v1/auth", "/api/auth"})
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody @Valid RegisterReq req) {
        log.info("Received register request for username: {}", req.username());
        authService.register(req);
        return ResponseEntity.status(HttpStatus.CREATED).body("Registered successfully");
    }

    /**
     * Endpoint đăng nhập: trả về cả Access Token và Refresh Token
     */
    @PostMapping("/login")
    public ResponseEntity<JwtRes> login(@RequestBody @Valid LoginReq req) {
        log.info("Received login request for username: {}", req.username());
        JwtRes jwtRes = authService.login(req);
        return ResponseEntity.ok(jwtRes);
    }

    /**
     * Endpoint cấp lại token (Token Rotation):
     * Nhận Refresh Token, kiểm tra tính hợp lệ, hủy token cũ và cấp phát một cặp Access Token + Refresh Token mới.
     * Note logic: Nếu token không tồn tại hoặc hết hạn, GlobalExceptionHandler sẽ trả về 403 Forbidden.
     *
     * @param req DTO chứa Refresh Token hiện tại
     * @return TokenResponseDTO chứa cặp token mới
     */
    @PostMapping("/refresh")
    public ResponseEntity<TokenResponseDTO> refreshToken(@RequestBody @Valid RefreshTokenReq req) {
        log.info("Received refresh token request");
        TokenResponseDTO response = authService.refreshToken(req);
        return ResponseEntity.ok(response);
    }
}
