package com.example.identityservice.models.dto.res;

import java.util.List;

public record JwtRes (
        String accessToken,
        String type,
        List<String> roles
) {
}
