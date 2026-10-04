package com.example.identityservice.security.jwt;


import com.example.identityservice.models.entities.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Component
public class JwtUtils {
    @Value("${app.jwt.secret}")
    private String secretKey;

    @Value("${app.jwt.access-token-expiration:900000}")
    private Long accessTokenExpiration;

    private Key signKey;

    @PostConstruct
    public void init() {
        byte[] bytes = Decoders.BASE64.decode(secretKey);
        this.signKey = Keys.hmacShaKeyFor(bytes);
    }

    // Lấy signing key từ Base64 secret (HMAC-SHA256 >= 256 bits)
    public Key getSignKey() {
        if (this.signKey == null) {
            init();
        }
        return this.signKey;
    }

    /**
     * Tạo Access Token (JWT) ngắn hạn chứa thông tin người dùng, vai trò (roles)
     * và claim định danh duy nhất jti (JWT ID) để hỗ trợ Blacklist/Revocation khi Logout.
     *
     * @param user đối tượng User chứa thông tin tài khoản và danh sách quyền
     * @return chuỗi JWT Access Token
     */
    public String generateAccessToken(User user) {
        List<String> roleNames = user.getRoles() != null
                ? user.getRoles().stream()
                    .map(role -> role.getRoleName().name())
                    .toList()
                : List.of();

        String jti = UUID.randomUUID().toString();

        Map<String, Object> claims = new HashMap<>();
        claims.put("username", user.getUsername());
        claims.put("roles", roleNames);
        claims.put(Claims.ID, jti);

        return Jwts.builder()
                .setClaims(claims)
                .setId(jti)
                .setSubject(user.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + accessTokenExpiration))
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // Giữ lại generateToken để tương thích ngược
    public String generateToken(User user) {
        return generateAccessToken(user);
    }

    /**
     * Giải mã toàn bộ Claims từ chuỗi JWT.
     */
    public Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * Trích xuất claim jti (JWT ID).
     */
    public String extractJti(String token) {
        return extractAllClaims(token).getId();
    }

    /**
     * Trích xuất thời điểm hết hạn (exp).
     */
    public Date extractExpiration(String token) {
        return extractAllClaims(token).getExpiration();
    }

    /**
     * Trích xuất username (subject).
     */
    public String extractUsername(String token) {
        return extractAllClaims(token).getSubject();
    }

    /**
     * Kiểm tra tính hợp lệ về chữ ký và hạn dùng của token.
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(getSignKey())
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
