package com.fc.userservice.service;


import com.fc.userservice.models.RefreshTokenEntity;
import com.fc.userservice.models.UserEntity;
import com.fc.userservice.repositories.RefreshTokenRepository;
import com.fc.userservice.repositories.UserRepository;
import com.fc.userservice.security.exception.TokenRefreshException;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
@Slf4j
public class RefreshTokenService {

    // Tiempo de expiración del refresh token (en milisegundos)
    // Por defecto, 7 días (7 * 24 * 60 * 60 * 1000)
    @Value("${jwt.refresh.expiration:604800000}")
    private Long refreshTokenDurationMs;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private UserRepository userRepository;

    /**
     * Crea un nuevo refresh token para un usuario
     */
    public RefreshTokenEntity createRefreshToken(String username) {
        UserEntity user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado: " + username));

        // Revocar tokens anteriores del usuario
        List<RefreshTokenEntity> existingTokens = refreshTokenRepository.findAllByUserAndRevokedFalseAndUsedFalse(user);
        String previousToken = null;

        if (!existingTokens.isEmpty()) {
            previousToken = existingTokens.get(0).getToken();
            existingTokens.forEach(token -> token.setUsed(true));
            refreshTokenRepository.saveAll(existingTokens);
        }

        RefreshTokenEntity refreshToken = RefreshTokenEntity.builder()
                .user(user)
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusMillis(refreshTokenDurationMs))
                .revoked(false)
                .used(false)
                .previousToken(previousToken)
                .build();

        return refreshTokenRepository.save(refreshToken);
    }

    /**
     * Busca un refresh token por su valor
     */
    public Optional<RefreshTokenEntity> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    /**
     * Guarda un refresh token
     */
    public RefreshTokenEntity save(RefreshTokenEntity refreshToken) {
        return refreshTokenRepository.save(refreshToken);
    }

    /**
     * Verifica si un refresh token es válido
     */
    public RefreshTokenEntity verifyExpiration(RefreshTokenEntity token) {
        if (token.isExpired()) {
            refreshTokenRepository.delete(token);
            throw new TokenRefreshException(token.getToken(), "Refresh token expirado. Por favor, inicie sesión nuevamente");
        }

        if (token.isRevoked()) {
            throw new TokenRefreshException(token.getToken(), "Refresh token revocado. Posible intento de reutilización");
        }

        if (token.isUsed()) {
            // Verificar si hay un intento de reutilización sospechoso
            checkForReplayAttack(token);
            throw new TokenRefreshException(token.getToken(), "Refresh token ya utilizado");
        }

        return token;
    }

    /**
     * Marca un refresh token como usado después de generar un nuevo token
     */
    public RefreshTokenEntity markAsUsed(RefreshTokenEntity refreshToken) {
        refreshToken.setUsed(true);
        return refreshTokenRepository.save(refreshToken);
    }

    /**
     * Revoca todos los refresh tokens de un usuario
     */
    @Transactional
    public int revokeAllUserTokens(UserEntity user) {
        List<RefreshTokenEntity> tokens = refreshTokenRepository.findAllByUserAndRevokedFalseAndUsedFalse(user);
        tokens.forEach(token -> token.setRevoked(true));
        refreshTokenRepository.saveAll(tokens);
        return tokens.size();
    }

    /**
     * Verifica si hay un intento de reutilización sospechoso de un token
     */
    private void checkForReplayAttack(RefreshTokenEntity token) {
        // Si un token usado se intenta usar nuevamente, revocamos toda la cadena
        // para prevenir ataques de replay
        Optional<RefreshTokenEntity> newerToken = refreshTokenRepository.findByPreviousToken(token.getToken());

        if (newerToken.isPresent()) {
            log.warn("Posible ataque de replay detectado para el usuario: {}", token.getUser().getUsername());

            // Revocar todos los tokens del usuario
            List<RefreshTokenEntity> userTokens = refreshTokenRepository.findAllByUserAndRevokedFalseAndUsedFalse(token.getUser());
            userTokens.forEach(t -> t.setRevoked(true));
            refreshTokenRepository.saveAll(userTokens);
        }
    }

    /**
     * Tarea programada para eliminar tokens expirados
     */
    @Scheduled(fixedRate = 86400000) // Ejecutar cada 24 horas
    @Transactional
    public void purgeExpiredTokens() {
        refreshTokenRepository.deleteAllExpiredTokens(Instant.now());
        log.info("Tokens expirados eliminados");
    }
}