package org.compairifuel.compairifuelapi.authorization.dataAccess;

import org.compairifuel.compairifuelapi.utils.IYamlLoader;

import org.compairifuel.compairifuelapi.authorization.dataAccess.AuthClient;

import java.util.Optional;
import java.util.stream.Stream;
import java.io.IOException;
import java.util.Optional;
import jakarta.inject.Inject;

public class HardcodedAuthClientRepositoryImpl implements IAuthClientRepository {
    private IYamlLoader yamlLoader;
    private static final String RESOURCE_NAME = "whitelisted_uri.yml";

    @Inject
    public void setYamlLoader(IYamlLoader yamlLoader) {
        this.yamlLoader = yamlLoader;
    }

    private Optional<AuthClient> findByClientId(String clientId) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(getClass()
                .getClassLoader()
                .getResources(RESOURCE_NAME).nextElement().openStream()))) {

                try(Stream<AuthClient> clients = yamlLoader.load(reader,AuthClient.class)){
                    return clients.filter(c -> clientId.equals(c.clientId)).findAny();
                }
                catch(IOException | UncheckedIOException ex){
                    return null;
                }
}
catch(IOException | UncheckedIOException ex){
                    return null;
                }

    }

    @Override
    public AuthClient getClientById(String clientId) {
        return findByClientId(clientId).orElse(null);
    }

    @Override
    public boolean isRedirectUriAllowed(String clientId, String redirectUri) {
        return findByClientId(clientId).filter(c -> c.enabled == true).map(c -> c.redirectUris).map(uris -> uris.contains(redirectUri)).orElse(false);
    }
}
