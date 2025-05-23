package com.fc.batchservice.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.List;
import java.util.function.Function;

@Slf4j
@Component
public class JwtUtils {

    @Value("${jwt.secret.key}")
    private String secretKey;

    @Value("${jwt.time.expiration}")
    private String timeExpiration;

    public String getUsernameFromToken(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public List<String> getRolesFromToken(String token) {
        return extractClaim(token, claims -> claims.get("roles", List.class));
    }

    public boolean isTokenValid(String token) {
        try {
            // Debug: Imprime información crítica
            log.debug("Validando token con clave: {}...", secretKey.substring(0, 10));
            log.debug("Token completo: {}...", token.substring(0, 20));

            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getSignatureKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            log.debug("Token válido para usuario: {}", claims.getSubject());
            return true;
        } catch (Exception e) {
            log.error("Fallo de validación: {}", e.getMessage());
            log.error("Clave usada: {}...", secretKey.substring(0, 10));
            return false;
        }
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public Claims extractAllClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(getSignatureKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
            log.error("Error al parsear token: {}", e.getMessage());
            throw new JwtException("Token inválido", e);
        }
    }

    private Key getSignatureKey() {
        try {
            byte[] keyBytes = Decoders.BASE64.decode(secretKey);
            return Keys.hmacShaKeyFor(keyBytes);
        } catch (Exception e) {
            log.error("Error procesando clave secreta. Valor actual: {}...", secretKey.substring(0, Math.min(secretKey.length(), 10)));
            throw new RuntimeException("Configuración JWT incorrecta", e);
        }
    }



}