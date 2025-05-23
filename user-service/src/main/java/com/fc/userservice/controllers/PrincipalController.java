package com.fc.userservice.controllers;

import com.fc.userservice.models.ERole;
import com.fc.userservice.models.RoleEntity;
import com.fc.userservice.models.UserEntity;
import com.fc.userservice.repositories.UserRepository;
import com.fc.userservice.dto.input.CreateUserDTO;
import com.fc.userservice.dto.input.LoginRequest;
import com.fc.userservice.security.jwt.JwtUtils;
import com.fc.userservice.service.UserDetailsServiceImpl;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api")
@Slf4j
public class PrincipalController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        try {
            // Autenticar al usuario
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

            // Establecer la autenticación en el contexto de seguridad
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // Obtener el usuario autenticado
            UserEntity user = userRepository.findByUsername(loginRequest.getUsername())
                    .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));

            // Obtener roles
            List<String> roles = user.getRoles().stream()
                    .map(role -> "ROLE_" + role.getName().name())
                    .collect(Collectors.toList());

            // Generar token JWT
            String jwt = jwtUtils.generateAccessToken(user.getUsername(), roles);

            // Crear respuesta
            Map<String, Object> response = new HashMap<>();
            response.put("token", jwt);
            response.put("username", authentication.getName());
            response.put("roles", roles);

            // Log para depuración
            log.info("Login exitoso - Username: {}", loginRequest.getUsername());

            return ResponseEntity.ok(response);
        } catch (BadCredentialsException e) {
            log.error("Credenciales inválidas para usuario: {}", loginRequest.getUsername());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Credenciales inválidas");
        } catch (Exception e) {
            log.error("Error en login: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error de autenticación");
        }
    }

    @PostMapping("/createUser")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> createUser(@Valid @RequestBody CreateUserDTO createUserDTO) {
        try {
            if (userRepository.findByUsername(createUserDTO.getUsername()).isPresent()) {
                return ResponseEntity.badRequest().body("El usuario ya existe");
            }

            Set<RoleEntity> roles = createUserDTO.getRoles().stream()
                    .map(role -> RoleEntity.builder()
                            .name(ERole.valueOf(role)).build())
                    .collect(Collectors.toSet());

            UserEntity userEntity = UserEntity.builder()
                    .username(createUserDTO.getUsername())
                    .password(passwordEncoder.encode(createUserDTO.getPassword()))
                    .email(createUserDTO.getEmail())
                    .enabled(createUserDTO.getEnabled())
                    .roles(roles)
                    .build();

            userRepository.save(userEntity);

            return ResponseEntity.ok("Usuario creado correctamente");
        } catch (Exception e) {
            log.error("Error al crear usuario: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error al crear usuario: " + e.getMessage());
        }
    }

    @DeleteMapping("/deleteUser/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> deleteUser(@PathVariable Long id) {
        if (!userRepository.existsById(id)) {
            return ResponseEntity.badRequest().body("El usuario no existe");
        }
        userRepository.deleteById(id);
        return ResponseEntity.ok("Usuario eliminado con éxito");
    }

    @DeleteMapping("/deleteUserByUsername/{username}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> deleteUserByUsername(@PathVariable String username) {
        UserEntity user = userRepository.findByUsername(username)
                .orElse(null);

        if (user == null) {
            return ResponseEntity.badRequest().body("El usuario no existe");
        }

        userRepository.delete(user);
        return ResponseEntity.ok("Usuario '" + username + "' eliminado con éxito");
    }

    @PatchMapping("/disableUser/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> disableUser(@PathVariable Long id) {
        UserEntity user = userRepository.findById(id)
                .orElse(null);

        if (user == null) {
            return ResponseEntity.badRequest().body("El usuario no existe");
        }

        user.setEnabled(false);
        userRepository.save(user);
        return ResponseEntity.ok("Usuario desactivado con éxito");
    }

    @PatchMapping("/enableUser/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> enableUser(@PathVariable Long id) {
        UserEntity user = userRepository.findById(id)
                .orElse(null);

        if (user == null) {
            return ResponseEntity.badRequest().body("El usuario no existe");
        }

        user.setEnabled(true);
        userRepository.save(user);
        return ResponseEntity.ok("Usuario activado con éxito");
    }

    @GetMapping("/users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<UserEntity>> getAllUsers() {
        List<UserEntity> users = (List<UserEntity>) userRepository.findAll();
        users.forEach(user -> user.setPassword(null));
        return ResponseEntity.ok(users);
    }

    @GetMapping("/users/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> getUserById(@PathVariable Long id) {
        UserEntity user = userRepository.findById(id)
                .orElse(null);

        if (user == null) {
            return ResponseEntity.notFound().build();
        }

        user.setPassword("[PROTECTED]");
        return ResponseEntity.ok(user);
    }

    @GetMapping("/test-users")
    public ResponseEntity<?> testUsers() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        Map<String, Object> response = new HashMap<>();
        response.put("username", auth.getName());
        response.put("authorities", auth.getAuthorities().stream()
                .map(a -> a.getAuthority())
                .collect(Collectors.toList()));
        response.put("isAuthenticated", auth.isAuthenticated());

        return ResponseEntity.ok(response);
    }

    @GetMapping("/debug-token")
    public ResponseEntity<?> debugToken(HttpServletRequest request) {
        String tokenHeader = request.getHeader("Authorization");
        Map<String, Object> response = new HashMap<>();

        if (tokenHeader != null && tokenHeader.startsWith("Bearer ")) {
            String token = tokenHeader.substring(7);
            try {
                String username = jwtUtils.getUsernameFromToken(token);
                List<String> roles = jwtUtils.getRolesFromToken(token);

                response.put("username", username);
                response.put("roles", roles);
                response.put("isTokenValid", jwtUtils.isTokenValid(token));

                Authentication auth = SecurityContextHolder.getContext().getAuthentication();
                if (auth != null) {
                    response.put("currentAuth", auth.getName());
                    response.put("currentAuthorities", auth.getAuthorities().stream()
                            .map(a -> a.getAuthority())
                            .collect(Collectors.toList()));
                    response.put("isAuthenticated", auth.isAuthenticated());
                }

                return ResponseEntity.ok(response);
            } catch (Exception e) {
                response.put("error", "Error al procesar token: " + e.getMessage());
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
            }
        } else {
            response.put("error", "No se proporcionó token");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
    }
}
