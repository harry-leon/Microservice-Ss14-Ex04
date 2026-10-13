package com.rikkei.microservice.identity.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class BlacklistTokenService {

    private final StringRedisTemplate stringRedisTemplate;

    private static final String BLACKLIST_KEY_PREFIX = "blacklist:";

    public void blacklistToken(String jti, long ttlMillis) {
        if (ttlMillis <= 0) {
            log.info("Token with jti {} has already expired or non-positive TTL, skipping redis blacklist", jti);
            return;
        }
        String key = BLACKLIST_KEY_PREFIX + jti;
        stringRedisTemplate.opsForValue().set(key, "revoked", ttlMillis, TimeUnit.MILLISECONDS);
        log.info("Token with jti {} successfully added to blacklist with TTL {} ms", jti, ttlMillis);
    }

    public boolean isBlacklisted(String jti) {
        if (jti == null) {
            return false;
        }
        String key = BLACKLIST_KEY_PREFIX + jti;
        Boolean exists = stringRedisTemplate.hasKey(key);
        return Boolean.TRUE.equals(exists);
    }
}
