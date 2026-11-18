package pe.gob.mtc.wallet.diagnostics.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ProviderServiceIdentityTest {
    @Test void allowsOnlyExplicitlyConfiguredOauthClient() {
        var identity=new ProviderServiceIdentity("mtc-wallet-provider-qa");
        assertTrue(identity.allowed(auth("mtc-wallet-provider-qa")));
        assertFalse(identity.allowed(auth("a-different-client")));
        assertFalse(new ProviderServiceIdentity("").allowed(auth("mtc-wallet-provider-qa")));
    }
    private JwtAuthenticationToken auth(String client) {
        var token=Jwt.withTokenValue("not-a-live-token").header("alg","RS256")
            .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60))
            .claim("client_id",client)
            .claim("scope","diagnostics.device.sync")
            .claim("aud",List.of("wallet-diagnostics"))
            .build();
        return new JwtAuthenticationToken(token);
    }
}
