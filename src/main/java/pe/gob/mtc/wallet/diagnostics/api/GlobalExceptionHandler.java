package pe.gob.mtc.wallet.diagnostics.api;

import jakarta.validation.ConstraintViolationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import pe.gob.mtc.wallet.diagnostics.domain.DiagnosticsException;

import java.time.Instant;
import java.util.UUID;

@RestControllerAdvice
public class GlobalExceptionHandler {
    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(DiagnosticsException.class)
    public ResponseEntity<SafeError> known(DiagnosticsException e) {
        return error(e.status(), e.code());
    }

    @ExceptionHandler({MethodArgumentNotValidException.class, ConstraintViolationException.class,
            HttpMessageNotReadableException.class, MethodArgumentTypeMismatchException.class})
    public ResponseEntity<SafeError> invalid(Exception ignored) {
        return error(HttpStatus.BAD_REQUEST, "INVALID_REQUEST");
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<SafeError> invalidArgument(IllegalArgumentException ignored) {
        return error(HttpStatus.BAD_REQUEST, "INVALID_REQUEST");
    }

    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<SafeError> storageUnavailable(DataAccessException ignored) {
        return error(HttpStatus.SERVICE_UNAVAILABLE, "DIAGNOSTIC_STORAGE_UNAVAILABLE");
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<SafeError> forbidden(AccessDeniedException ignored) {
        return error(HttpStatus.FORBIDDEN, "ACCESS_DENIED");
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<SafeError> unexpected(Exception ignored) {
        return error(HttpStatus.INTERNAL_SERVER_ERROR, "UNEXPECTED_ERROR");
    }

    private ResponseEntity<SafeError> error(HttpStatus status, String code) {
        var error = new SafeError(code, Instant.now(), UUID.randomUUID());
        // No registrar detalles de excepciones, firmas o cuerpo. Limitar ruido de
        // solicitudes no autorizadas para evitar inundación de archivos.
        if (status.is5xxServerError()) {
            log.error("DIAGNOSTIC_REQUEST_FAILED trackingId={} status={} code={}",
                    error.trackingId(), status.value(), code);
        } else if (status.value() == 409 || status.value() == 413) {
            log.warn("DIAGNOSTIC_REQUEST_REJECTED trackingId={} status={} code={}",
                    error.trackingId(), status.value(), code);
        }
        return ResponseEntity.status(status).body(error);
    }

    public record SafeError(String code, Instant timestamp, UUID trackingId) {}
}
