package com.finsec.fuse.reimplementation.http;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.http.HttpServletRequest;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Objects;

/** Application-visible HTTP bounds. The servlet container still needs its own transport limits. */
public final class RequestGuard {
    private final HttpLimits limits;

    public RequestGuard(HttpLimits limits) { this.limits = Objects.requireNonNull(limits); }

    public CachedBodyRequest inspect(HttpServletRequest request) throws IOException {
        Objects.requireNonNull(request);
        if (request.isAsyncStarted() || request.getDispatcherType() == DispatcherType.ASYNC) {
            throw rejected(PublicHttpErrors.Error.DEPENDENCY_UNAVAILABLE);
        }
        inspectHeaders(request);
        if (singleHeader(request, "Content-Encoding") != null) {
            throw rejected(PublicHttpErrors.Error.UNSUPPORTED_MEDIA_TYPE);
        }
        String media = singleHeader(request, "Content-Type");
        if (media != null) inspectMedia(media);
        String lengthHeader = singleHeader(request, "Content-Length");
        String transfer = singleHeader(request, "Transfer-Encoding");
        if (transfer != null && (lengthHeader != null || !transfer.trim().equalsIgnoreCase("chunked"))) {
            throw rejected(PublicHttpErrors.Error.INVALID_REQUEST);
        }
        long declared = lengthHeader == null ? request.getContentLengthLong() : contentLength(lengthHeader);
        if (declared > limits.maxBodyBytes()) throw rejected(PublicHttpErrors.Error.REQUEST_TOO_LARGE);
        byte[] body = readBounded(request);
        if (declared >= 0 && declared != body.length) throw rejected(PublicHttpErrors.Error.INVALID_REQUEST);
        boolean requiresJson = "POST".equals(request.getMethod()) || "PUT".equals(request.getMethod())
                || "PATCH".equals(request.getMethod()) || body.length != 0;
        if (requiresJson) {
            if (media == null) throw rejected(PublicHttpErrors.Error.UNSUPPORTED_MEDIA_TYPE);
            StrictJsonInspector.verify(body, limits.maxJsonDepth());
        }
        return new CachedBodyRequest(request, body, transfer != null);
    }

    private void inspectHeaders(HttpServletRequest request) {
        long remaining = limits.maxHeaderBytes();
        Enumeration<String> names = request.getHeaderNames();
        if (names == null) throw rejected(PublicHttpErrors.Error.INVALID_REQUEST);
        while (names.hasMoreElements()) {
            String name = names.nextElement();
            if (name == null) throw rejected(PublicHttpErrors.Error.INVALID_REQUEST);
            Enumeration<String> values = request.getHeaders(name);
            if (values == null) throw rejected(PublicHttpErrors.Error.INVALID_REQUEST);
            while (values.hasMoreElements()) {
                String value = values.nextElement();
                if (value == null) throw rejected(PublicHttpErrors.Error.INVALID_REQUEST);
                remaining = subtract(remaining, name);
                remaining = subtract(remaining, value);
                if (remaining < 4) throw rejected(PublicHttpErrors.Error.HEADERS_TOO_LARGE);
                remaining -= 4; // Colon/SP and CRLF for each application-visible header value.
            }
        }
    }

    private static long subtract(long remaining, String text) {
        for (int at = 0; at < text.length(); at++) {
            char unit = text.charAt(at);
            int bytes;
            if (unit <= 0x7f) bytes = 1;
            else if (unit <= 0x7ff) bytes = 2;
            else if (Character.isHighSurrogate(unit)) {
                if (++at >= text.length() || !Character.isLowSurrogate(text.charAt(at))) {
                    throw rejected(PublicHttpErrors.Error.INVALID_REQUEST);
                }
                bytes = 4;
            } else {
                if (Character.isLowSurrogate(unit)) throw rejected(PublicHttpErrors.Error.INVALID_REQUEST);
                bytes = 3;
            }
            if (remaining < bytes) throw rejected(PublicHttpErrors.Error.HEADERS_TOO_LARGE);
            remaining -= bytes;
        }
        return remaining;
    }

    private static String singleHeader(HttpServletRequest request, String name) {
        Enumeration<String> values = request.getHeaders(name);
        if (values == null || !values.hasMoreElements()) return null;
        String value = values.nextElement();
        if (value == null || values.hasMoreElements()) {
            throw rejected(name.equals("Content-Type") || name.equals("Content-Encoding")
                    ? PublicHttpErrors.Error.UNSUPPORTED_MEDIA_TYPE : PublicHttpErrors.Error.INVALID_REQUEST);
        }
        return value;
    }

    private static void inspectMedia(String raw) {
        String[] parts = raw.split(";", -1);
        if (parts.length > 2 || !parts[0].trim().equalsIgnoreCase("application/json")) {
            throw rejected(PublicHttpErrors.Error.UNSUPPORTED_MEDIA_TYPE);
        }
        if (parts.length == 2) {
            String parameter = parts[1].trim();
            int equals = parameter.indexOf('=');
            if (equals < 0 || !parameter.substring(0, equals).trim().equalsIgnoreCase("charset")) {
                throw rejected(PublicHttpErrors.Error.UNSUPPORTED_MEDIA_TYPE);
            }
            String charset = parameter.substring(equals + 1).trim();
            if (!(charset.equalsIgnoreCase("UTF-8") || charset.equalsIgnoreCase("\"UTF-8\""))) {
                throw rejected(PublicHttpErrors.Error.UNSUPPORTED_MEDIA_TYPE);
            }
        }
    }

    private static long contentLength(String raw) {
        String value = raw.trim();
        if (value.isEmpty()) throw rejected(PublicHttpErrors.Error.INVALID_REQUEST);
        long length = 0;
        for (int at = 0; at < value.length(); at++) {
            char digit = value.charAt(at);
            if (digit < '0' || digit > '9') throw rejected(PublicHttpErrors.Error.INVALID_REQUEST);
            int number = digit - '0';
            if (length > (Long.MAX_VALUE - number) / 10) {
                throw rejected(PublicHttpErrors.Error.REQUEST_TOO_LARGE);
            }
            length = length * 10 + number;
        }
        return length;
    }

    private byte[] readBounded(HttpServletRequest request) throws IOException {
        int maximum = limits.maxBodyBytes();
        var result = new ByteArrayOutputStream(Math.min(maximum, 4096));
        byte[] buffer = new byte[Math.min(maximum, 8192)];
        var input = request.getInputStream();
        int total = 0;
        while (true) {
            int remaining = maximum - total;
            int wanted = remaining >= buffer.length ? buffer.length : remaining + 1;
            int read = input.read(buffer, 0, wanted);
            if (read < 0) return result.toByteArray();
            if (read == 0) {
                int next = input.read();
                if (next < 0) return result.toByteArray();
                if (remaining == 0) throw rejected(PublicHttpErrors.Error.REQUEST_TOO_LARGE);
                result.write(next);
                total++;
            } else {
                if (read > remaining) throw rejected(PublicHttpErrors.Error.REQUEST_TOO_LARGE);
                result.write(buffer, 0, read);
                total += read;
            }
        }
    }

    private static PublicHttpErrors.Rejected rejected(PublicHttpErrors.Error error) {
        return new PublicHttpErrors.Rejected(error);
    }
}
