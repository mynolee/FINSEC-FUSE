FROM eclipse-temurin:21-jdk AS build
WORKDIR /workspace
COPY gradlew build.gradle settings.gradle ./
COPY gradle gradle
COPY backend/src backend/src
COPY evaluation/fixtures evaluation/fixtures
RUN chmod +x gradlew && ./gradlew --no-daemon --console=plain bootJar
FROM eclipse-temurin:21-jre
WORKDIR /app
RUN groupadd -g 10001 fuse && useradd -u 10001 -g fuse -s /usr/sbin/nologin fuse
COPY --from=build /workspace/backend/build/libs/finsec-fuse-0.1.0-SNAPSHOT.jar app.jar
# Standalone image defaults to an unprivileged identity. Developer Compose
# selects the non-root host UID/GID so its bind-mounted 0600 secret stays private.
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
