package com.fc.userservice.dto.output;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DatabaseStatusResponse {

    private LocalDateTime timestamp;
    private boolean allConnectionsOk;
    private Map<String, DatabaseConnectionStatus> connections;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class DatabaseConnectionStatus {
        private boolean connected;
        private String message;
        private String details;
    }

    public static DatabaseStatusResponse createSuccessResponse() {
        Map<String, DatabaseConnectionStatus> connections = new HashMap<>();
        connections.put("main", DatabaseConnectionStatus.builder()
                .connected(true)
                .message("Conexión exitosa a la base de datos principal")
                .build());
        connections.put("users", DatabaseConnectionStatus.builder()
                .connected(true)
                .message("Conexión exitosa a la base de datos de usuarios")
                .build());

        return DatabaseStatusResponse.builder()
                .timestamp(LocalDateTime.now())
                .allConnectionsOk(true)
                .connections(connections)
                .build();
    }

    public static DatabaseStatusResponse createErrorResponse(String dbName, String errorMessage, String details) {
        Map<String, DatabaseConnectionStatus> connections = new HashMap<>();

        // Agregar la base de datos con error
        connections.put(dbName, DatabaseConnectionStatus.builder()
                .connected(false)
                .message(errorMessage)
                .details(details)
                .build());

        // Agregar la otra base de datos como desconocida si es necesario
        String otherDb = "main".equals(dbName) ? "users" : "main";
        connections.put(otherDb, DatabaseConnectionStatus.builder()
                .connected(false)
                .message("Estado desconocido")
                .build());

        return DatabaseStatusResponse.builder()
                .timestamp(LocalDateTime.now())
                .allConnectionsOk(false)
                .connections(connections)
                .build();
    }
}