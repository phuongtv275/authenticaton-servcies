package com.example.identityservice.models.dto.req;

public record RegisterReq(
        String fullName,
        String username,
        String password
) {
}
