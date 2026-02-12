package org.compairifuel.compairifuelapi.authorization.dataaccess;

import org.compairifuel.compairifuelapi.utils.IYamlLoader;

import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Stream;
import java.io.IOException;
import jakarta.inject.Inject;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.InputStream;
import java.io.UncheckedIOException;
import lombok.extern.java.Log;
import jakarta.enterprise.inject.Default;
import org.apache.commons.codec.digest.DigestUtils;
import org.compairifuel.compairifuelapi.utils.NoCoverageGenerated;

@Log(topic = "HardcodedAuthClientRepositoryImpl")
@Default
public class HardcodedAuthClientRepositoryImpl implements IAuthClientRepository {
    private IYamlLoader yamlLoader;
    private static final String RESOURCE_NAME = "whitelisted_client.yml";

    @Inject
    public void setYamlLoader(IYamlLoader yamlLoader) {
        this.yamlLoader = yamlLoader;
    }

    private Optional<AuthClient> findByClientId(String clientId) {
        try (InputStream in = openResource()) {
            if (in == null) {
                return Optional.empty();
            }

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(in));
                Stream<AuthClient> clients = yamlLoader.load(reader, AuthClient.class)) {

                return clients
                        .filter(c -> clientId.equals(c.clientId))
                        .findAny();
            }
        }
        catch (IOException | UncheckedIOException e) {
            return Optional.empty();
        }
    }

    @Override
    public AuthClient getClientByIdAndSecret(String clientId, String clientSecret) {
        return findByClientId(clientId).filter(c -> isClientSecretValid(clientSecret).test(c)).orElse(null);
    }

    @Override
    public boolean isClientIdAndSecretAllowed(String clientId, String clientSecret) {
        return findByClientId(clientId).filter(c -> c.enabled && isClientSecretValid(clientSecret).test(c)).isPresent();
    }

    @Override
    public boolean  isRedirectUriAllowed(String clientId, String clientSecret, String redirectUri) {
        return findByClientId(clientId).filter(c -> c.enabled && isClientSecretValid(clientSecret).test(c)).map(c -> c.redirectUris.contains(redirectUri)).orElse(false);
    }

    @NoCoverageGenerated
    protected InputStream openResource() {
        return getClass()
            .getClassLoader()
            .getResourceAsStream(RESOURCE_NAME);
    }

    private Predicate<AuthClient> isClientSecretValid(String providedSecret) {
        return c -> c.clientSecret == null ? providedSecret == null : Arrays.equals(Base64.getUrlDecoder().decode(c.clientSecret), DigestUtils.sha256(providedSecret));
    }
}
