# Uses an OpenJDK image for Java
FROM openjdk:17-alpine

# Sets the working directory
WORKDIR /app

# Copy the JAR file built in the container
COPY target/supply-service-0.0.1-SNAPSHOT.jar app.jar

# Establece la zona horaria a Ecuador
RUN apk add --no-cache tzdata \
    && cp /usr/share/zoneinfo/America/Guayaquil /etc/localtime \
    && echo "America/Guayaquil" > /etc/timezone \

# Expone el puerto en el que la aplicación se ejecutará
EXPOSE 8081

# Comando para ejecutar la aplicación
CMD ["java", "-jar", "app.jar"]
