package com.example.identityservice.models.services;

import com.example.identityservice.models.dto.req.LoginReq;
import com.example.identityservice.models.dto.req.RefreshTokenReq;
import com.example.identityservice.models.dto.req.RegisterReq;
import com.example.identityservice.models.dto.res.JwtRes;
import com.example.identityservice.models.dto.res.TokenResponseDTO;

public interface AuthService {

    void register(RegisterReq req);

    JwtRes login(LoginReq req);

    TokenResponseDTO refreshToken(RefreshTokenReq req);

    void logout(String token);
}
