package com.finsec.fuse.common;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.transaction.CannotCreateTransactionException;
import org.springframework.transaction.TransactionSystemException;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

@RestControllerAdvice
public final class ApiErrorHandler {
    private static final Logger LOG=LoggerFactory.getLogger(ApiErrorHandler.class);
    @ExceptionHandler(ApiException.class)
    public ResponseEntity<Map<String,Object>> api(ApiException error,HttpServletRequest request) {
        return response(error.status(),error.reasonCode(),error.getMessage(),request);
    }
    @ExceptionHandler({HttpMessageNotReadableException.class,MethodArgumentNotValidException.class,ConstraintViolationException.class,MethodArgumentTypeMismatchException.class,MissingRequestHeaderException.class})
    public ResponseEntity<Map<String,Object>> invalid(Exception ignored,HttpServletRequest request) {
        return response(400,"INVALID_REQUEST","Request does not match the API contract",request);
    }
    // Connection loss can surface while starting or rolling back/committing a transaction,
    // after the original DataAccessException has been wrapped by the transaction manager.
    // An uncertain DB outcome must never be translated into a policy denial or payment claim.
    @ExceptionHandler({DataAccessException.class,CannotCreateTransactionException.class,TransactionSystemException.class})
    public ResponseEntity<Map<String,Object>> unavailable(RuntimeException error,HttpServletRequest request) {
        LOG.error("Database operation failed: {}",error.getClass().getSimpleName());
        return response(503,"DEPENDENCY_UNAVAILABLE","The operation outcome cannot be confirmed. After recovery, check using the same action ID and unchanged request",request);
    }
    private ResponseEntity<Map<String,Object>> response(int status,String code,String message,HttpServletRequest request) {
        UUID action=null;
        try { if(request.getHeader("Idempotency-Key")!=null) action=com.finsec.fuse.config.PublicUuidConfiguration.parseCanonical(request.getHeader("Idempotency-Key")); }
        catch(IllegalArgumentException ignored) {}
        return ResponseEntity.status(status).body(Json.ordered("requestId",action,"workflowId",null,"generation",null,"state",null,
            "decision",status>=500?"ERROR":"DENY","reasonCodes",List.of(code),"message",message,"replayed",false));
    }
}
