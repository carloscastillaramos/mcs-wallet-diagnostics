package pe.gob.mtc.wallet.diagnostics.infrastructure;

import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import pe.gob.mtc.wallet.diagnostics.domain.DiagnosticsException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class ProviderDeviceSyncRepositoryTest {
    private final JdbcTemplate jdbc=mock(JdbcTemplate.class);
    private final ProviderDeviceSyncRepository repository=new ProviderDeviceSyncRepository(jdbc);
    private static final String DEVICE="c31a1641-d7fa-4e22-bd4e-fc54b2f5ef49";
    @Test void newDeviceIsInsertedOnceWithAudit() {
        when(jdbc.queryForObject(contains("SELECT EXISTS"),eq(Boolean.class),eq(DEVICE),eq("k1"))).thenReturn(false);
        when(jdbc.update(contains("INSERT INTO wallet_diagnostics.mcs_diag_device "),any(Object[].class))).thenReturn(1);
        repository.register(DEVICE,"k1","ANDROID","spki","wallet-provider");
        verify(jdbc).update(contains("mcs_diag_admin_audit"),any(Object[].class));
    }
    @Test void tombstonedDeviceCannotBeResurrected() {
        when(jdbc.queryForObject(contains("SELECT EXISTS"),eq(Boolean.class),eq(DEVICE),eq("k1"))).thenReturn(true);
        repository.register(DEVICE,"k1","IOS","spki","wallet-provider");
        verify(jdbc,never()).update(contains("INSERT INTO wallet_diagnostics.mcs_diag_device "),any(Object[].class));
    }
    @Test void existingKeyWithDifferentMaterialIsRejected() {
        when(jdbc.queryForObject(contains("SELECT EXISTS"),eq(Boolean.class),eq(DEVICE),eq("k1"))).thenReturn(false);
        when(jdbc.update(contains("INSERT INTO wallet_diagnostics.mcs_diag_device "),any(Object[].class))).thenReturn(0);
        when(jdbc.query(contains("SELECT (platform=?"),any(org.springframework.jdbc.core.RowMapper.class),
                eq("IOS"),eq("spki"),eq(DEVICE),eq("k1"))).thenReturn(List.of(false));
        assertThrows(DiagnosticsException.class,()->repository.register(DEVICE,"k1","IOS","spki","provider"));
    }
    @Test void firstRevocationCreatesTombstoneEvenIfRegistrationNeverArrived() {
        when(jdbc.update(contains("INSERT INTO wallet_diagnostics.mcs_diag_device_tombstone"),
                any(Object[].class))).thenReturn(1,0);
        repository.revoke(DEVICE,"k1","provider");
        repository.revoke(DEVICE,"k1","provider");
        verify(jdbc,times(1)).update(contains("mcs_diag_admin_audit"),any(Object[].class));
    }
}
