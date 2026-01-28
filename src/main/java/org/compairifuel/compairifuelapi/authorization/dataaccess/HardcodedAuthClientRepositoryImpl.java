package org.compairifuel.compairifuelapi.authorization.dataaccess;

import org.compairifuel.compairifuelapi.utils.IYamlLoader;

import java.util.Optional;
import java.util.stream.Stream;
import java.io.IOException;
import jakarta.inject.Inject;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.InputStream;
import java.io.UncheckedIOException;

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
    public AuthClient getClientById(String clientId) {
        return findByClientId(clientId).orElse(null);
    }

    @Override
    public boolean isRedirectUriAllowed(String clientId, String redirectUri) {
        return findByClientId(clientId).filter(c -> c.enabled).map(c -> c.redirectUris.contains(redirectUri)).orElse(false);
    }

    protected InputStream openResource() {
        return getClass()
            .getClassLoader()
            .getResourceAsStream(RESOURCE_NAME);
    }
}
