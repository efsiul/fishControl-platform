# Usa una imagen base liviana de OpenJDK 17
FROM openjdk:17-alpine

# Establece el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copia el JAR generado por Maven al contenedor
COPY target/batch-service-0.0.1-SNAPSHOT.jar app.jar

# Establece la zona horaria a Guayaquil, Ecuador
RUN apk add --no-cache tzdata && \
    cp /usr/share/zoneinfo/America/Guayaquil /etc/localtime \
    && echo "America/Guayaquil" > /etc/timezone \

# Expone el puerto en el que Spring Boot se ejecuta
EXPOSE 8082

# Comando para ejecutar el microservicio
CMD ["java", "-jar", "app.jar"]
