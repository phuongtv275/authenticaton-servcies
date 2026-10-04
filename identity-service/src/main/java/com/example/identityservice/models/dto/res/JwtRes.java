package com.example.identityservice.models.dto.res;

import java.util.List;

public record JwtRes(
        String accessToken,
        String refreshToken,
        String type,
        List<String> roles
) {
    public JwtRes(String accessToken, String refreshToken, List<String> roles) {
        this(accessToken, refreshToken, "Bearer", roles);
    }
}
