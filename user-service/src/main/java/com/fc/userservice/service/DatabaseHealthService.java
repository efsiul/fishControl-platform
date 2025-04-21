package com.fc.userservice.service;

import com.fc.userservice.dto.output.DatabaseStatusResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

@Service
@Slf4j
public class DatabaseHealthService {

    @Autowired
    private DataSource userDataSource;

    public DatabaseStatusResponse checkDatabaseConnections() {
        Map<String, DatabaseStatusResponse.DatabaseConnectionStatus> connections = new HashMap<>();
        boolean allOk = true;

        try (Connection conn = userDataSource.getConnection()) {
            if (conn.isValid(5)) {
                connections.put("users", DatabaseStatusResponse.DatabaseConnectionStatus.builder()
                        .connected(true)
                        .message("Conexión exitosa a la base de datos de usuarios")
                        .build());
            } else {
                allOk = false;
                connections.put("users", DatabaseStatusResponse.DatabaseConnectionStatus.builder()
                        .connected(false)
                        .message("La conexión a la base de datos de usuarios no es válida")
                        .build());
            }
        } catch (SQLException e) {
            allOk = false;
            log.error("Error al conectar a la base de datos de usuarios: {}", e.getMessage());
            connections.put("users", DatabaseStatusResponse.DatabaseConnectionStatus.builder()
                    .connected(false)
                    .message("Error al conectar a la base de datos de usuarios")
                    .details(e.getMessage())
                    .build());
        }

        return DatabaseStatusResponse.builder()
                .timestamp(java.time.LocalDateTime.now())
                .allConnectionsOk(allOk)
                .connections(connections)
                .build();
    }
}
