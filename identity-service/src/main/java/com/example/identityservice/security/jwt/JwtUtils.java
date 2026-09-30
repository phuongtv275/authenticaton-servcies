package com.example.identityservice.security.jwt;


import com.example.identityservice.models.entities.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
public class JwtUtils {
    @Value("${jwt.secret-key:${jwt.secret}}")
    private String secretKey;

    @Value("${jwt.expired:${jwt.expired-access-token}}")
    private Long expiredAccessToken;

//    Bam key
    public Key getSignKey() {
        byte[] bytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(bytes);
    }

//    Generate token
    public String generateToken(User user) {
        // Serialize roles thành List<String> (ví dụ: ["ROLE_ADMIN", "ROLE_USER"])
        // để Gateway có thể extract trực tiếp từ Claims mà không cần parse object phức tạp
        List<String> roleNames = user.getRoles().stream()
                .map(role -> role.getRoleName().name())
                .toList();

        Map<String, Object> claims = new HashMap<>();
        claims.put("username", user.getUsername());
        claims.put("roles", roleNames);

        return createToken(claims, user.getUsername());
    }

//    Create token
    private String createToken(Map<String, Object> claims, String username) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expiredAccessToken))
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }
}
