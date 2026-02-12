package org.compairifuel.compairifuelapi.authorization.dataaccess;

public interface IAuthClientRepository {
    AuthClient getClientByIdAndSecret(String clientId, String clientSecret);
    boolean isClientIdAndSecretAllowed(String clientId, String clientSecret);
    boolean isRedirectUriAllowed(String clientId, String clientSecret, String redirectUri);
}
