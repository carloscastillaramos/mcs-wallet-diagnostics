package pe.gob.mtc.wallet.diagnostics.infrastructure;

import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import pe.gob.mtc.wallet.diagnostics.domain.DiagnosticEvent;
import pe.gob.mtc.wallet.diagnostics.domain.DiagnosticsException;
import pe.gob.mtc.wallet.diagnostics.domain.StoredDiagnosticEvent;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class PostgresDiagnosticsRepositoryTest {
    private static final String DEVICE = "22f4303c-9c70-469c-a0d2-c78147e21bfa";

    @Test
    void nonceReservationUsesOnConflict() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        when(jdbc.update(contains("mcs_diag_nonce"), any(Object[].class))).thenReturn(1, 0);
        var repo = new PostgresDiagnosticsRepository(jdbc);
        assertTrue(repo.reserveNonce(DEVICE, "nonce-1"));
        assertFalse(repo.reserveNonce(DEVICE, "nonce-1"));
    }

    @Test
    void duplicateEventWithSameHashIsAcknowledgedWithoutReinsert() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        var repo = new PostgresDiagnosticsRepository(jdbc);
        when(jdbc.update(contains("mcs_diag_event_registry"), any(Object[].class))).thenReturn(0);
        when(jdbc.query(contains("SELECT payload_sha256"), any(org.springframework.jdbc.core.RowMapper.class),
                eq(DEVICE), anyString())).thenReturn(List.of("abc123"));
        assertFalse(repo.insertEvent(DEVICE, event("abc123")));
        verify(jdbc, never()).update(contains("mcs_diag_event("), any(Object[].class));
    }

    @Test
    void duplicateEventWithDifferentHashReturnsConflict() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        var repo = new PostgresDiagnosticsRepository(jdbc);
        when(jdbc.update(contains("mcs_diag_event_registry"), any(Object[].class))).thenReturn(0);
        when(jdbc.query(contains("SELECT payload_sha256"), any(org.springframework.jdbc.core.RowMapper.class),
                eq(DEVICE), anyString())).thenReturn(List.of("other-hash"));
        assertEquals("CONFLICTING_EVENT_ID", assertThrows(DiagnosticsException.class,
                () -> repo.insertEvent(DEVICE, event("abc123"))).code());
    }

    private StoredDiagnosticEvent event(String hash) {
        var e = new DiagnosticEvent(UUID.fromString("8c53c6e7-cf3f-4693-9710-705e7d24c91e"),
                Instant.parse("2026-11-06T01:59:45Z"), "DOWNLOAD_ERROR", "WALLET", "ERROR",
                "NETWORK_TIMEOUT", "ANDROID", "1.0.0", 1000L, Map.of());
        return new StoredDiagnosticEvent(e, "{}", hash, Instant.parse("2026-11-06T02:00:00Z"));
    }
}
