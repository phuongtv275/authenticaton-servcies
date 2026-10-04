package com.example.identityservice.models.dto.req;

import jakarta.validation.constraints.NotBlank;

public record RegisterReq(
        @NotBlank(message = "Full name cannot be blank")
        String fullName,

        @NotBlank(message = "Username cannot be blank")
        String username,

        @NotBlank(message = "Password cannot be blank")
        String password
) {
}
