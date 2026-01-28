package org.compairifuel.compairifuelapi.authorization.dataaccess;

public interface IAuthClientRepository {
    AuthClient getClientById(String clientId);
    boolean isRedirectUriAllowed(String clientId, String redirectUri);
}
