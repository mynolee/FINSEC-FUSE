FROM eclipse-temurin:21-jdk AS build
WORKDIR /workspace
COPY gradlew build.gradle settings.gradle ./
COPY gradle gradle
COPY backend/src backend/src
COPY evaluation/fixtures evaluation/fixtures
RUN chmod +x gradlew && ./gradlew --no-daemon --console=plain bootJar databaseMigrationJar tokenAdminJar
FROM eclipse-temurin:21-jre AS runtime-base
WORKDIR /app
RUN groupadd -g 10001 fuse && useradd -u 10001 -g fuse -s /usr/sbin/nologin fuse

FROM runtime-base AS migration
COPY --from=build /workspace/backend/build/libs/finsec-fuse-0.1.0-SNAPSHOT-migration.jar app.jar
USER 10001:10001
# No default operation: starting this image without explicit arguments fails closed.
ENTRYPOINT ["java", "-jar", "/app/app.jar"]

FROM runtime-base AS token-admin
# Nonsecret host identity only. Owner passwords and bearer values are NEVER build arguments.
ARG FUSE_ADMIN_UID
ARG FUSE_ADMIN_GID
RUN case "$FUSE_ADMIN_UID" in ''|0*|*[!0-9]*) exit 1;; esac \
 && case "$FUSE_ADMIN_GID" in ''|0*|*[!0-9]*) exit 1;; esac \
 && test "$FUSE_ADMIN_UID" -lt 2147483647 && test "$FUSE_ADMIN_GID" -lt 2147483647 \
 && groupadd --non-unique -g "$FUSE_ADMIN_GID" fuse_admin \
 && useradd --non-unique -u "$FUSE_ADMIN_UID" -g fuse_admin -M -s /usr/sbin/nologin fuse_admin
COPY --from=build /workspace/backend/build/libs/finsec-fuse-0.1.0-SNAPSHOT-token-admin.jar app.jar
USER ${FUSE_ADMIN_UID}:${FUSE_ADMIN_GID}
ENTRYPOINT ["java", "-jar", "/app/app.jar"]

# Keep the normal web runtime LAST as well as explicitly selected by Compose.
FROM runtime-base AS backend
COPY --from=build /workspace/backend/build/libs/finsec-fuse-0.1.0-SNAPSHOT.jar app.jar
# Standalone image defaults to an unprivileged identity. Developer Compose
# selects the non-root host UID/GID so its bind-mounted 0600 secret stays private.
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
