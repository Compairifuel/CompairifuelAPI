package org.compairifuel.compairifuelapi.authorization.service;

import org.compairifuel.compairifuelapi.authorization.service.domain.AccessTokenDomain;

import java.net.URI;

public interface IAuthorizationService {
    URI getAuthorizationCode(String grantType, String clientId, String clientSecret, String redirectUri, String codeChallenge, String state, String scope);
    AccessTokenDomain getAccessToken(String grantType, String authorizationCode, String redirectUri, String clientId, String clientSecret, String codeVerifier);
    AccessTokenDomain getAccessTokenByRefreshToken(String grantType, String refreshToken, String clientId, String clientSecret, String codeVerifier);
}
