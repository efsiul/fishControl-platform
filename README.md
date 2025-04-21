# FishControl Platform

FishControl es una plataforma de microservicios construida con Spring Boot y Docker. Esta arquitectura permite separar los distintos dominios del sistema, cada uno con su lógica y gestión de datos independiente, pero compartiendo una única base de datos, con distintas instancias.

---

## 📦 Servicios

- **discovery-service**: Registro de servicios con Eureka.
- **gateway-service**: Entrada centralizada (API Gateway).
- **user-service**: Gestión de usuarios y autenticación.
- **supply-service**: Gestión de suministros.
- **fc-db**: Instancia PostgreSQL que contiene las sub-bases de datos: `user_db`, `supply_db`.

---

## ⚙️ Requisitos Previos

- [Docker](https://docs.docker.com/get-docker/)
- [Docker Compose](https://docs.docker.com/compose/)
- Java 17 (para desarrollo local sin Docker)

---

## 🚀 Clonar el repositorio

   ```bash
   git clone https://github.com/tu-usuario/fishcontrol-platform.git
   cd fishcontrol-platform
   ```

## 📦 Estructura del Proyecto
```arm
.
├── docker-compose.yml
├── init-db/
│   └── init.sql
├── discovery-service/
├── gateway-service/
├── user-service/
└── supply-service/
```

## 📆 Pasos para el Despliegue

### 1. Construir los servicios
```bash
  mvn clean package install
```

### 2. Iniciar los servicios
```bash
  docker-compose up --build -d
```

### 3. Acceder a los servicios
- **Eureka Discovery Service**: [http://localhost:8761](http://localhost:8761)
- **API Gateway**: [http://localhost:8080](http://localhost:8080)
- **User Service**: [http://localhost:8080/user-service](http://localhost:8080/user-service)
- **Supply Service**: [http://localhost:8080/supply-service](http://localhost:8080/supply-service)
- **PostgreSQL**: [http://localhost:5432](http://localhost:5433)
  - Usuario: `postgres`
  - Contraseña: `postgres`
  - Base de datos: `fc_db`

### 4. Verificar el estado de los servicios
```bash
  docker-compose ps
```


