package org.compairifuel.compairifuelapi.authorization.dataAccess;

public interface IAuthClientRepository {
    AuthClient getClientById(String clientId);
    boolean isRedirectUriAllowed(String clientId, String redirectUri);
}
