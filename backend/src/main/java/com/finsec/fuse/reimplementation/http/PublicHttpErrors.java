package com.finsec.fuse.reimplementation.http;

import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

/** Fixed public rendering only. This class does not make authentication or authority decisions. */
public final class PublicHttpErrors {
    public enum Error {
        INVALID_REQUEST(400, "INVALID_REQUEST"),
        UNAUTHENTICATED(401, "UNAUTHENTICATED"),
        FORBIDDEN(403, "FORBIDDEN"),
        METHOD_NOT_ALLOWED(405, "METHOD_NOT_ALLOWED"),
        NOT_ACCEPTABLE(406, "NOT_ACCEPTABLE"),
        REQUEST_TOO_LARGE(413, "REQUEST_TOO_LARGE"),
        UNSUPPORTED_MEDIA_TYPE(415, "UNSUPPORTED_MEDIA_TYPE"),
        HEADERS_TOO_LARGE(431, "REQUEST_TOO_LARGE"),
        DEPENDENCY_UNAVAILABLE(503, "DEPENDENCY_UNAVAILABLE");

        private final int status;
        private final String code;

        Error(int status, String code) { this.status = status; this.code = code; }
        public int status() { return status; }
        public String code() { return code; }
    }

    /** No caller text, exception cause, raw input, or stack trace is retained. */
    public static final class Rejected extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final Error error;

        public Rejected(Error error) {
            super(Objects.requireNonNull(error).code(), null, false, false);
            this.error = error;
        }

        public Error error() { return error; }
    }

    public static Error forStatus(int status) {
        for (Error error : Error.values()) {
            if (error.status() == status) return error;
        }
        throw new IllegalArgumentException("Unsupported public error status");
    }

    public ResponseEntity<Map<String, Object>> response(Error error) {
        Objects.requireNonNull(error);
        return ResponseEntity.status(error.status()).contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("decision", "ERROR", "reasonCodes", List.of(error.code()),
                        "message", error.code()));
    }

    /** Clear only replaced body metadata; preserve mode, security and CORS policy. */
    boolean prepareReplacement(HttpServletResponse response) {
        Objects.requireNonNull(response);
        if (response.isCommitted()) return false;
        response.resetBuffer();
        // The buffered representation is being replaced, not its mode/security/CORS policy.
        // Old encodings, validators, range and digest metadata describe different bytes.
        for (String name : List.of("Content-Encoding", "Transfer-Encoding", "Trailer",
                "Content-Range", "Accept-Ranges", "Content-MD5", "Digest", "Content-Digest",
                "Repr-Digest", "ETag", "Last-Modified", "Content-Location", "Content-Disposition")) {
            response.setHeader(name, null);
        }
        response.setHeader("Content-Length", null);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        return true;
    }

    /** Returns false when an already committed response cannot safely be replaced. */
    public boolean write(HttpServletResponse response, Error error) throws IOException {
        Objects.requireNonNull(response); Objects.requireNonNull(error);
        if (response.isCommitted()) return false;
        byte[] body = ("{\"decision\":\"ERROR\",\"reasonCodes\":[\"" + error.code()
                + "\"],\"message\":\"" + error.code() + "\"}").getBytes(StandardCharsets.UTF_8);
        if (!prepareReplacement(response)) return false;
        response.setStatus(error.status());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentLength(body.length);
        response.getOutputStream().write(body);
        return true;
    }
}
