package pe.gob.mtc.wallet.diagnostics.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

/** A dedicated workload OAuth client, not merely a JWT with an admin scope. */
@Component("providerServiceIdentity")
public class ProviderServiceIdentity {
    private final String expectedClientId;
    public ProviderServiceIdentity(@Value("${MCS_PROVIDER_SYNC_CLIENT_ID:}") String expectedClientId) {
        this.expectedClientId=expectedClientId;
    }
    public boolean allowed(Authentication authentication) {
        if(expectedClientId.isBlank() || !(authentication instanceof JwtAuthenticationToken jwt)) return false;
        String clientId=jwt.getToken().getClaimAsString("client_id");
        if(clientId==null) clientId=jwt.getToken().getClaimAsString("azp");
        return expectedClientId.equals(clientId);
    }
}
