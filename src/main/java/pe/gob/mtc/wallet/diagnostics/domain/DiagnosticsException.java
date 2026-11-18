package pe.gob.mtc.wallet.diagnostics.domain;

import org.springframework.http.HttpStatus;

public class DiagnosticsException extends RuntimeException {
    private final HttpStatus status;
    private final String code;

    public DiagnosticsException(HttpStatus status, String code) {
        super(code);
        this.status = status;
        this.code = code;
    }
    public HttpStatus status() { return status; }
    public String code() { return code; }
    public static DiagnosticsException invalid() {
        return new DiagnosticsException(HttpStatus.BAD_REQUEST, "INVALID_DIAGNOSTIC_PAYLOAD");
    }
    public static DiagnosticsException unauthorized() {
        return new DiagnosticsException(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED_DEVICE");
    }
    public static DiagnosticsException replay() {
        return new DiagnosticsException(HttpStatus.CONFLICT, "REPLAYED_REQUEST");
    }
    public static DiagnosticsException conflict() {
        return new DiagnosticsException(HttpStatus.CONFLICT, "CONFLICTING_EVENT_ID");
    }
    public static DiagnosticsException tooLarge() {
        return new DiagnosticsException(HttpStatus.PAYLOAD_TOO_LARGE, "PAYLOAD_TOO_LARGE");
    }
}
