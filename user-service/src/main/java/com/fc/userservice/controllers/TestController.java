package com.fc.userservice.controllers;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

@RestController
@RequestMapping("/api/test")
@Slf4j
public class TestController {

    @Autowired
    private DataSource userDataSource;

    /**
     * Endpoint para simular un error en la base de datos de usuarios
     */
    @GetMapping("/error-user-db")
    public ResponseEntity<String> simulateUserDbError() {
        try (Connection conn = userDataSource.getConnection()) {
            try (Statement stmt = conn.createStatement()) {
                stmt.execute("SELECT * FROM tabla_que_no_existe");
            }
            return ResponseEntity.ok("Este mensaje no debería mostrarse");
        } catch (SQLException e) {
            log.error("Error simulado en la base de datos de usuarios: {}", e.getMessage());
            return ResponseEntity.internalServerError().body("Error simulado correctamente: " + e.getMessage());
        }
    }

    @GetMapping("/test-users")
    public ResponseEntity<String> testUsers() {
        return ResponseEntity.ok("Endpoint de prueba funcionando correctamente");
    }

} 