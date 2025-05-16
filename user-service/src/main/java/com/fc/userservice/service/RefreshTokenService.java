package com.fc.userservice.service;

import com.fc.userservice.models.RefreshTokenEntity;
import com.fc.userservice.models.UserEntity;
import com.fc.userservice.repositories.RefreshTokenRepository;
import com.fc.userservice.repositories.UserRepository;
import com.fc.userservice.security.exception.TokenRefreshException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {

    @Value("${jwt.refresh.expiration:604800000}")
    private Long refreshTokenDurationMs;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private UserRepository userRepository;

    public RefreshTokenEntity createRefreshToken(String username) {
        UserEntity user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado: " + username));

        RefreshTokenEntity refreshToken = RefreshTokenEntity.builder()
                .user(user)
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusMillis(refreshTokenDurationMs))
                .revoked(false)
                .used(false)
                .build();

        return refreshTokenRepository.save(refreshToken);
    }

    public Optional<RefreshTokenEntity> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    public RefreshTokenEntity save(RefreshTokenEntity refreshToken) {
        return refreshTokenRepository.save(refreshToken);
    }

    public RefreshTokenEntity verifyExpiration(RefreshTokenEntity token) {
        if (token.isExpired()) {
            refreshTokenRepository.delete(token);
            throw new TokenRefreshException(token.getToken(), "Refresh token was expired. Please make a new login");
        }
        return token;
    }

    public RefreshTokenEntity markAsUsed(RefreshTokenEntity token) {
        token.setUsed(true);
        return refreshTokenRepository.save(token);
    }
}
