package pe.gob.mtc.wallet.diagnostics.application;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.validation.Validation;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import pe.gob.mtc.wallet.diagnostics.application.port.DiagnosticsRepository;
import pe.gob.mtc.wallet.diagnostics.config.DiagnosticsProperties;
import pe.gob.mtc.wallet.diagnostics.domain.DeviceIdentity;
import pe.gob.mtc.wallet.diagnostics.domain.DiagnosticsException;
import pe.gob.mtc.wallet.diagnostics.domain.StoredDiagnosticEvent;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class IngestionServiceTest {
    private static final Instant NOW = Instant.parse("2026-11-06T02:00:00Z");
    private static final DeviceIdentity DEVICE =
            new DeviceIdentity("22f4303c-9c70-469c-a0d2-c78147e21bfa", "wallet-01");
    private static jakarta.validation.ValidatorFactory factory;

    @BeforeAll
    static void initialize() { factory = Validation.buildDefaultValidatorFactory(); }
    @AfterAll
    static void stop() { factory.close(); }

    private IngestionService create(DiagnosticsRepository repository) {
        return new IngestionService(repository,
                new ObjectMapper().registerModule(new JavaTimeModule()),
                factory.getValidator(), new DiagnosticsProperties(65536, 50, 300, 8),
                Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    void acceptsThenAcknowledgesDuplicateEvent() {
        var repo = mock(DiagnosticsRepository.class);
        when(repo.reserveNonce(anyString(), anyString())).thenReturn(true);
        when(repo.insertEvent(eq(DEVICE.deviceId()), any(StoredDiagnosticEvent.class))).thenReturn(true, false);
        var service = create(repo);
        var first = service.accept(DEVICE, "first_unique_nonce_1", batch());
        var again = service.accept(DEVICE, "second_unique_nonce_2", batch());
        assertEquals(1, first.accepted());
        assertEquals(0, first.duplicates());
        assertEquals(0, again.accepted());
        assertEquals(1, again.duplicates());
        verify(repo, times(2)).insertEvent(eq(DEVICE.deviceId()), any(StoredDiagnosticEvent.class));
    }

    @Test
    void rejectsReplayEvenWhenBodyIsIdentical() {
        var repo = mock(DiagnosticsRepository.class);
        when(repo.reserveNonce(anyString(), anyString())).thenReturn(false);
        assertEquals("REPLAYED_REQUEST", assertThrows(DiagnosticsException.class,
                () -> create(repo).accept(DEVICE, "reused_nonce_12345", batch())).code());
        verify(repo, never()).insertEvent(anyString(), any());
    }

    @Test
    void rejectsSensitiveOrUnapprovedAttributes() {
        var repo = mock(DiagnosticsRepository.class);
        byte[] unsafe = new String(batch(), StandardCharsets.UTF_8)
                .replace("\"NETWORK_STATE\":\"ONLINE\"", "\"DNI\":\"12345678\"")
                .getBytes(StandardCharsets.UTF_8);
        assertThrows(DiagnosticsException.class, () -> create(repo).accept(DEVICE, "nonce_new_1234567", unsafe));
        verifyNoInteractions(repo);
    }

    @Test
    void rejectsMalformedEventWithoutInsertingNonce() {
        var repo = mock(DiagnosticsRepository.class);
        byte[] malformed = new String(batch(), StandardCharsets.UTF_8)
                .replace("\"platform\":\"ANDROID\"", "\"platform\":\"DESKTOP\"")
                .getBytes(StandardCharsets.UTF_8);
        assertThrows(DiagnosticsException.class, () -> create(repo).accept(DEVICE, "nonce_new_1234567", malformed));
        verifyNoInteractions(repo);
    }

    private byte[] batch() {
        return ("""
                {"events":[{
                  "eventId":"8c53c6e7-cf3f-4693-9710-705e7d24c91e",
                  "occurredAt":"2026-11-06T01:59:45Z",
                  "eventType":"DOWNLOAD_ERROR",
                  "component":"WALLET",
                  "severity":"ERROR",
                  "code":"SSOIUGO_TOKEN_TIMEOUT",
                  "platform":"ANDROID",
                  "appVersion":"1.0.0",
                  "durationMs":15000,
                  "attributes":{"NETWORK_STATE":"ONLINE"}
                }]}
                """).getBytes(StandardCharsets.UTF_8);
    }
}
