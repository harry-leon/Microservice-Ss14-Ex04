package com.rikkei.microservice.identity.service;

import com.rikkei.microservice.identity.entity.User;
import com.rikkei.microservice.identity.repository.UserRepository;
import com.rikkei.microservice.identity.security.JwtUtils;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final JwtUtils jwtUtils;
    private final BlacklistTokenService blacklistTokenService;
    private final RefreshTokenService refreshTokenService;
    private final UserRepository userRepository;

    @Transactional
    public void logout(String token) {
        // 1. Giải mã token để lấy claim "jti" và "exp" (thời gian hết hạn).
        Claims claims = jwtUtils.getClaimsFromJwtToken(token);
        String jti = claims.getId();
        Date expiration = claims.getExpiration();

        if (jti == null) {
            throw new IllegalArgumentException("Token does not contain a valid JTI claim");
        }

        // 2. Tính toán TTL (Time-To-Live): TTL = exp - thời gian hiện tại.
        long now = System.currentTimeMillis();
        long ttl = expiration != null ? (expiration.getTime() - now) : 0;

        // 3. Lưu key "blacklist:{jti}" vào Redis với giá trị "revoked".
        // 4. Thiết lập thời gian tự động xóa (Expiration) cho key này trong Redis bằng đúng TTL.
        if (ttl > 0) {
            blacklistTokenService.blacklistToken(jti, ttl);
        }

        // 5. (Tùy chọn): Xóa luôn Refresh Token tương ứng trong PostgreSQL.
        String username = claims.getSubject();
        if (username != null) {
            userRepository.findByUsername(username).ifPresent(user -> {
                refreshTokenService.deleteByUserId(user.getId());
                log.info("Deleted refresh token for user: {}", username);
            });
        }
    }
}
