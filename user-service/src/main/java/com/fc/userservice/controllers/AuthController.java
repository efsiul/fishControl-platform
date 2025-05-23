package com.fc.userservice.controllers;

import com.fc.userservice.models.RefreshTokenEntity;
import com.fc.userservice.dto.input.TokenRefreshRequest;
import com.fc.userservice.dto.output.TokenRefreshResponse;
import com.fc.userservice.security.exception.TokenRefreshException;
import com.fc.userservice.security.jwt.JwtUtils;
import com.fc.userservice.service.RefreshTokenService;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "http://localhost:5173")
@Slf4j
public class AuthController {

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private RefreshTokenService refreshTokenService;

    @PostMapping("/refreshtoken")
    public ResponseEntity<?> refreshToken(@Valid @RequestBody TokenRefreshRequest request) {
        String requestRefreshToken = request.getRefreshToken();

        try {

            return refreshTokenService.findByToken(requestRefreshToken)
                    .map(refreshTokenService::verifyExpiration)
                    .map(RefreshTokenEntity::getUser)
                    .map(user -> {
                        List<String> roles = user.getRoles().stream()
                                .map(role -> "ROLE_" + role.getName().name())
                                .toList();
                        // Generar nuevo access token
                        String token = jwtUtils.generateAccessToken(user.getUsername(), roles);

                        // Marcar el refresh token actual como usado
                        RefreshTokenEntity usedToken = refreshTokenService.findByToken(requestRefreshToken)
                                .map(refreshTokenService::markAsUsed)
                                .orElseThrow(() -> new TokenRefreshException(requestRefreshToken,
                                        "Refresh token no encontrado"));

                        // Crear un nuevo refresh token
                        RefreshTokenEntity newRefreshToken = refreshTokenService.createRefreshToken(user.getUsername());

                        log.info("Token renovado exitosamente para el usuario: {}", user.getUsername());

                        return ResponseEntity.ok(new TokenRefreshResponse(token, newRefreshToken.getToken()));
                    })
                    .orElseThrow(() -> new TokenRefreshException(requestRefreshToken, "Refresh token no encontrado"));
        } catch (TokenRefreshException e) {
            log.error("Error al renovar token: {}", e.getMessage());
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logoutUser(@Valid @RequestBody TokenRefreshRequest request) {
        String refreshToken = request.getRefreshToken();

        return refreshTokenService.findByToken(refreshToken)
                .map(token -> {
                    // Revocar el refresh token
                    token.setRevoked(true);
                    refreshTokenService.save(token);

                    log.info("Usuario desconectado exitosamente: {}", token.getUser().getUsername());

                    return ResponseEntity.ok("Sesión cerrada exitosamente");
                })
                .orElse(ResponseEntity.ok("Sesión cerrada exitosamente"));
    }
}