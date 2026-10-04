package com.example.identityservice.models.services;

import com.example.identityservice.models.dto.res.TokenResponseDTO;
import com.example.identityservice.models.entities.RefreshToken;
import com.example.identityservice.models.entities.User;

import java.util.Optional;

public interface RefreshTokenService {

    RefreshToken createRefreshToken(Long userId);

    RefreshToken createRefreshToken(User user);

    RefreshToken verifyExpiration(RefreshToken token);

    Optional<RefreshToken> findByToken(String token);

    int deleteByUserId(Long userId);

    int deleteByUser(User user);

    TokenResponseDTO refreshToken(String requestToken);
}
