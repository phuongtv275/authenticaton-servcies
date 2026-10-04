package com.example.identityservice.models.services.impl;

import com.example.identityservice.exceptions.NotFoundException;
import com.example.identityservice.exceptions.TokenRefreshException;
import com.example.identityservice.models.entities.RefreshToken;
import com.example.identityservice.models.entities.User;
import com.example.identityservice.models.repositories.RefreshTokenRepository;
import com.example.identityservice.models.repositories.UserRepository;
import com.example.identityservice.models.services.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class RefreshTokenServiceImpl implements RefreshTokenService {

    @Value("${app.jwt.refresh-token-expiration:604800000}")
    private Long refreshTokenDurationMs;

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;

    /**
     * Tạo mới Refresh Token dạng UUID và lưu thông tin hạn sử dụng xuống cơ sở dữ liệu.
     * Note logic: Tìm kiếm User, xóa token cũ (nếu có) để đảm bảo mỗi phiên đăng nhập mới
     * sẽ sở hữu token duy nhất, tránh token rác tích tụ trong database.
     *
     * @param userId mã định danh của User cần cấp token
     * @return đối tượng RefreshToken đã lưu
     */
    @Override
    @Transactional
    public RefreshToken createRefreshToken(Long userId) {
        log.info("Creating refresh token for userId: {}", userId);
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new NotFoundException("User not found with id: " + userId));

        // Dọn dẹp token cũ của user (nếu có) bằng atomic delete để tránh NonUniqueResultException
        refreshTokenRepository.deleteByUser(user);

        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusMillis(refreshTokenDurationMs))
                .build();

        RefreshToken saved = refreshTokenRepository.save(refreshToken);
        log.info("Successfully created refresh token id: {} for userId: {}", saved.getId(), userId);
        return saved;
    }

    /**
     * Xác thực xem Refresh Token đã hết hạn hay chưa.
     * Note logic: So sánh expiryDate với Instant.now().
     * Nếu đã hết hạn, xóa bản ghi khỏi DB để dọn dẹp và ném TokenRefreshException.
     * Cấu hình noRollbackFor để đảm bảo lệnh delete vẫn được commit xuống DB khi ném exception.
     *
     * @param token RefreshToken cần kiểm tra
     * @return token hợp lệ nếu chưa hết hạn
     */
    @Override
    @Transactional(noRollbackFor = TokenRefreshException.class)
    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            log.warn("Refresh token [{}] expired at {}", token.getToken(), token.getExpiryDate());
            refreshTokenRepository.delete(token);
            throw new TokenRefreshException(token.getToken(), "Refresh token was expired. Please make a new signin request");
        }
        return token;
    }

    @Override
    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    @Override
    @Transactional
    public int deleteByUserId(Long userId) {
        log.info("Deleting refresh tokens for userId: {}", userId);
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new NotFoundException("User not found with id: " + userId));
        return refreshTokenRepository.deleteByUser(user);
    }
}
