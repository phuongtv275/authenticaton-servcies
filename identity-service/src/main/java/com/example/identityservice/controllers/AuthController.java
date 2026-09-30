package com.example.identityservice.controllers;

import com.example.identityservice.models.dto.req.LoginReq;
import com.example.identityservice.models.dto.req.RegisterReq;
import com.example.identityservice.models.services.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterReq req) {
        authService.register(req);
        return ResponseEntity.status(201).body("Registered successfully");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginReq req) {
        return ResponseEntity.ok(authService.login(req));
    }
}
