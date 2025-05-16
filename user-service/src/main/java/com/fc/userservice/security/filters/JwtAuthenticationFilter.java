package com.fc.userservice.security.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fc.userservice.models.RefreshTokenEntity;
import com.fc.userservice.models.UserEntity;
import com.fc.userservice.security.jwt.JwtUtils;
import com.fc.userservice.service.RefreshTokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final JwtUtils jwtUtils;
    private final RefreshTokenService refreshTokenService;

    public JwtAuthenticationFilter(JwtUtils jwtUtils, AuthenticationManager authenticationManager, RefreshTokenService refreshTokenService) {
        this.jwtUtils = jwtUtils;
        this.refreshTokenService = refreshTokenService;
        setAuthenticationManager(authenticationManager);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {
        UserEntity userEntity;
        String username;
        String password;
        try {
            userEntity = new ObjectMapper().readValue(request.getInputStream(), UserEntity.class);
            username = userEntity.getUsername();
            password = userEntity.getPassword();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(username, password);

        return getAuthenticationManager().authenticate(authenticationToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        User user = (User) authResult.getPrincipal();

        // Extraer los roles del usuario
        List<String> roles = user.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        // Generar el token JWT
        String token = jwtUtils.generateAccessToken(user.getUsername(), roles);

        // Generar refresh token
        RefreshTokenEntity refreshToken = refreshTokenService.createRefreshToken(user.getUsername());

        // Agregar el token al encabezado de la respuesta
        response.addHeader("Authorization", "Bearer " + token);

        // Crear la respuesta JSON
        Map<String, Object> httpResponse = new HashMap<>();
        httpResponse.put("token", token);
        httpResponse.put("refreshToken", refreshToken.getToken());
        httpResponse.put("message", "Autenticación correcta");
        httpResponse.put("username", user.getUsername());
        httpResponse.put("roles", roles);

        // Enviar la respuesta
        response.getWriter().write(new ObjectMapper().writeValueAsString(httpResponse));
        response.setStatus(HttpStatus.OK.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().flush();

        log.info("Inicio de sesión exitoso - Usuario: {} - Roles: {}",
                user.getUsername(), roles);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request,
                                              HttpServletResponse response,
                                              AuthenticationException failed) throws IOException, ServletException {
        log.error("Error de autenticación: {} - Usuario: desconocido",
                failed.getMessage());

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("status", HttpStatus.UNAUTHORIZED.value());
        errorResponse.put("error", "Unauthorized");

        if (failed instanceof BadCredentialsException) {
            errorResponse.put("message", "Credenciales inválidas");
        } else {
            errorResponse.put("message", failed.getMessage());
        }

        errorResponse.put("path", request.getRequestURI());

        new ObjectMapper().writeValue(response.getOutputStream(), errorResponse);
    }
}