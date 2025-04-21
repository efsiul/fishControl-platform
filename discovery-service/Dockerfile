# Uses an Eclipse Temurin image for Java
FROM eclipse-temurin:17-jdk-alpine

# Sets the working directory
WORKDIR /app

# Copy the JAR file built in the container
COPY target/discovery-service-0.0.1-SNAPSHOT.jar app.jar

# Copy the properties file to the working directory
COPY src/main/resources/application.properties application.properties

# Establece la zona horaria a Ecuador
RUN apk add --no-cache tzdata \
    && cp /usr/share/zoneinfo/America/Guayaquil /etc/localtime \
    && echo "America/Guayaquil" > /etc/timezone \
# Expone el puerto en el que la aplicación se ejecutará
EXPOSE 8961

# Comando para ejecutar la aplicación
CMD ["java", "-jar", "app.jar"]
