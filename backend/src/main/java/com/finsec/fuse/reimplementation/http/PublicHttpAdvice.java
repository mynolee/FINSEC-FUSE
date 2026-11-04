package com.finsec.fuse.reimplementation.http;

import jakarta.servlet.http.HttpServletResponse;
import java.util.Map;
import java.util.Objects;
import org.springframework.beans.TypeMismatchException;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.BindException;
import org.springframework.web.ErrorResponseException;
import org.springframework.web.HttpMediaTypeNotAcceptableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/** Instantiate explicitly with the fixed renderer; no messages, causes, or input are returned or logged. */
@RestControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
public final class PublicHttpAdvice {
    private final PublicHttpErrors errors;

    public PublicHttpAdvice(PublicHttpErrors errors) { this.errors = Objects.requireNonNull(errors); }

    @ExceptionHandler(PublicHttpErrors.Rejected.class)
    public ResponseEntity<Map<String, Object>> rejected(PublicHttpErrors.Rejected rejected, HttpServletResponse target) {
        return replacement(target, rejected.error());
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<Map<String, Object>> method(HttpRequestMethodNotSupportedException failure, HttpServletResponse target) {
        var response = replacement(target, PublicHttpErrors.Error.METHOD_NOT_ALLOWED);
        if (response == null) return null;
        var allowed = failure.getSupportedHttpMethods();
        if (allowed == null || allowed.isEmpty()) return response;
        return ResponseEntity.status(response.getStatusCode()).contentType(MediaType.APPLICATION_JSON)
                .allow(allowed.toArray(HttpMethod[]::new)).body(response.getBody());
    }

    @ExceptionHandler(HttpMediaTypeNotAcceptableException.class)
    public ResponseEntity<Map<String, Object>> acceptance(HttpServletResponse target) {
        return replacement(target, PublicHttpErrors.Error.NOT_ACCEPTABLE);
    }

    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<Map<String, Object>> media(HttpServletResponse target) {
        return replacement(target, PublicHttpErrors.Error.UNSUPPORTED_MEDIA_TYPE);
    }

    @ExceptionHandler({HttpMessageNotReadableException.class, BindException.class,
            ServletRequestBindingException.class, TypeMismatchException.class, IllegalArgumentException.class})
    public ResponseEntity<Map<String, Object>> invalid(HttpServletResponse target) {
        return replacement(target, PublicHttpErrors.Error.INVALID_REQUEST);
    }

    /** Preserve a framework's already chosen whitelisted status, discarding its reason and detail. */
    @ExceptionHandler(ErrorResponseException.class)
    public ResponseEntity<Map<String, Object>> framework(ErrorResponseException failure, HttpServletResponse target) {
        PublicHttpErrors.Error error;
        try {
            error = PublicHttpErrors.forStatus(failure.getStatusCode().value());
        } catch (IllegalArgumentException unsupported) {
            error = PublicHttpErrors.Error.DEPENDENCY_UNAVAILABLE;
        }
        return replacement(target, error);
    }

    private ResponseEntity<Map<String, Object>> replacement(HttpServletResponse target, PublicHttpErrors.Error error) {
        return errors.prepareReplacement(target) ? errors.response(error) : null;
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> unavailable(HttpServletResponse target) {
        return replacement(target, PublicHttpErrors.Error.DEPENDENCY_UNAVAILABLE);
    }
}
