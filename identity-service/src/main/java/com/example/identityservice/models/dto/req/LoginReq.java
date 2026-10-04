package com.example.identityservice.models.dto.req;

import jakarta.validation.constraints.NotBlank;

public record LoginReq(
        @NotBlank(message = "Username cannot be blank")
        String username,

        @NotBlank(message = "Password cannot be blank")
        String password
) {
}
