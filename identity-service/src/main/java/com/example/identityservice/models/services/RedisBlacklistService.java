package com.example.identityservice.models.services;

public interface RedisBlacklistService {

    /**
     * Ghi token vào danh sách đen (Blacklist) trong Redis.
     * Trích xuất jti và exp, tính TTL và lưu key "blacklist:{jti}" với giá trị "revoked".
     *
     * @param token chuỗi Access Token cần thu hồi
     */
    void blacklistToken(String token);

    /**
     * Kiểm tra xem một jti (JWT ID) có nằm trong danh sách đen hay không.
     *
     * @param jti JWT ID cần kiểm tra
     * @return true nếu đã bị thu hồi/nằm trong blacklist, ngược lại false
     */
    boolean isBlacklisted(String jti);
}
