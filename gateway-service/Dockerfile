# Uses an OpenJDK image for Java
FROM openjdk:17-alpine

# Sets the working directory
WORKDIR /app

# Copy the properties file to the working directory
COPY src/main/resources/application.yml application.yml

# Copy the JAR file built in the container
COPY target/gateway-service-0.0.1-SNAPSHOT.jar app.jar

# Establece la zona horaria a Ecuador
RUN apk add --no-cache tzdata \
    && cp /usr/share/zoneinfo/America/Guayaquil /etc/localtime \
    && echo "America/Guayaquil" > /etc/timezone

# Expone el puerto en el que la aplicación se ejecutará
EXPOSE 7777

# Comando para ejecutar la aplicación
CMD ["java", "-Dserver.port=7777", "-jar", "app.jar"]
