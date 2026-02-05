package org.compairifuel.compairifuelapi.authorization.service;

import io.jsonwebtoken.Claims;
import jakarta.enterprise.inject.Default;
import jakarta.inject.Inject;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.InternalServerErrorException;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.core.UriBuilder;
import lombok.Cleanup;
import lombok.extern.java.Log;
import org.apache.commons.codec.digest.DigestUtils;
import org.compairifuel.compairifuelapi.authorization.service.domain.AccessTokenDomain;
import org.compairifuel.compairifuelapi.authorization.dataaccess.IAuthClientRepository;
import static jakarta.ws.rs.core.Response.Status.UNAUTHORIZED;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpResponse;
import java.util.*;
import java.util.stream.Stream;

@Log(topic = "AuthorizationServiceImpl")
@Default
public class AuthorizationServiceImpl implements IAuthorizationService {
    private AuthCodeValidatorServiceImpl authCodeValidatorService;

    private IAuthClientRepository clientAuthRepository;

    @Inject
    public void setClientAuthRepository(IAuthClientRepository clientAuthRepository) {
        this.clientAuthRepository = clientAuthRepository;
    }

    @Inject
    public void setAuthCodeValidatorService(AuthCodeValidatorServiceImpl authCodeValidatorService) {
        this.authCodeValidatorService = authCodeValidatorService;
    }

    @Override
    public URI getAuthorizationCode(String grantType, String clientId, String clientSecret, String redirectUri, String codeChallenge, String state, String scope) {
        UriBuilder redirectToURI = UriBuilder.fromUri(redirectUri);

        boolean isWhitelisted = clientAuthRepository.isRedirectUriAllowed(clientId,clientSecret,redirectUri);

        if (!isWhitelisted) {
            log.warning("The consumer isn't whitelisted!");
            throw new ForbiddenException();
        }

        if(Stream.of(scope.split(" ")).noneMatch(s -> clientAuthRepository.getClientByIdAndSecret(clientId,clientSecret).roles.contains(s.split(":")[0]))) {
            log.warning("The consumer doesn't have the required role for the requested scope!");
            throw new ForbiddenException();
        }

        long expiresIn = 600; // 10 minutes 

        var hashMap = new HashMap<String, Object>();
        hashMap.put("state", state);
        hashMap.put("code_challenge", codeChallenge);
        String authorizationCode = authCodeValidatorService.createJwtsToken(hashMap, new Date(System.currentTimeMillis() + expiresIn), new Date(System.currentTimeMillis()), clientId, scope);

        return redirectToURI
                .queryParam("state", state)
                .queryParam("code", authorizationCode)
                .build();
    }

    @Override
    public AccessTokenDomain getAccessToken(String grantType, String authorizationCode, String redirectUri, String clientId, String clientSecret, String codeVerifier) {
        Claims claims = authCodeValidatorService.retrieveJwtsClaims(authorizationCode, "CompairifuelAPI", List.of());

        try {
            if (!isAuthorized(claims, redirectUri, clientId, clientSecret, codeVerifier)) {
                log.warning("The consumer is not authorized!");
                throw new NotAuthorizedException(UNAUTHORIZED.getReasonPhrase());
            }

        } catch (ForbiddenException ex) {
            log.warning("The consumer is not authorized to get an access token with the provided authorization code: " + ex.getMessage());
            throw new NotAuthorizedException(UNAUTHORIZED.getReasonPhrase());
        }

        return createAndBuildAccessTokenDomain(claims, clientId, null);
    }

    @Override
    public AccessTokenDomain getAccessTokenByRefreshToken(String grantType, String refreshToken, String clientId, String clientSecret, String codeVerifier) {
        Claims claims = authCodeValidatorService.retrieveJwtsClaims(refreshToken, "CompairifuelAPI", List.of());

        try {
            if (!isAuthorized(claims, clientId, clientSecret, codeVerifier)) {
                log.warning("The consumer is not authorized!");
                throw new NotAuthorizedException(UNAUTHORIZED.getReasonPhrase());
            }

        } catch (ForbiddenException ex) {
            log.warning("The consumer is not authorized to get a new access token with the provided refresh token: " + ex.getMessage());
            throw new NotAuthorizedException(UNAUTHORIZED.getReasonPhrase());
        }

        if (claims.getExpiration().after(new Date(System.currentTimeMillis() + authCodeValidatorService.getExpiresIn()))) {
            log.info("The refresh token is still valid, the access token will be renewed without creating a new refresh token.");
            return createAndBuildAccessTokenDomain(claims, clientId, refreshToken);
        }
        
        return createAndBuildAccessTokenDomain(claims, clientId, null);
    }

    private AccessTokenDomain createAndBuildAccessTokenDomain(Claims claims, String clientId, String refreshToken) {
        String scope = claims.get("scope", String.class);
        String accessToken = authCodeValidatorService.createJwtsToken(new HashMap<>(), new Date(System.currentTimeMillis() + authCodeValidatorService.getExpiresIn()), new Date(System.currentTimeMillis()), clientId, scope);

        if (refreshToken == null) {
            HashMap<String, Object> refreshTokenMap = new HashMap<>();
            refreshTokenMap.put("code_challenge", claims.get("code_challenge", String.class));
            refreshToken = authCodeValidatorService.createJwtsToken(refreshTokenMap, new Date(System.currentTimeMillis() + (authCodeValidatorService.getExpiresIn() * 2)), new Date(System.currentTimeMillis()), clientId, scope);
        }

        AccessTokenDomain accessTokenDomain = new AccessTokenDomain();
        accessTokenDomain.setAccessToken(accessToken);
        accessTokenDomain.setExpiresIn(authCodeValidatorService.getExpiresIn());
        accessTokenDomain.setTokenType(authCodeValidatorService.getTokenType());
        accessTokenDomain.setRefreshToken(refreshToken);
        return accessTokenDomain;
    }

    private boolean isAuthorized(Claims claims, String redirectUri, String clientId, String clientSecret, String codeVerifier) {
        if (!redirectUri.equals(claims.get("redirect_uri", String.class))){
            log.warning("The redirect URI doesn't match the one in the claims!");
            throw new ForbiddenException();
        }

        if (!clientAuthRepository.isRedirectUriAllowed(clientId, clientSecret, redirectUri)) {
            log.warning("The consumer isn't whitelisted!");
            throw new NotAuthorizedException(UNAUTHORIZED.getReasonPhrase());
        }

        return isAuthorized(claims, clientId, clientSecret, codeVerifier);
    }

    private boolean isAuthorized(Claims claims, String clientId, String clientSecret, String codeVerifier) {
        if (!clientId.equals(claims.getSubject())) {
            log.warning("The client ID doesn't match the subject in the claims!");
            throw new ForbiddenException();
        }

        if (!claims.getIssuer().equals("Compairifuel")) {
            log.warning("The issuer in the claims is not valid!");
            throw new ForbiddenException();
        }

        if (!Arrays.equals(Base64.getUrlDecoder().decode(claims.get("code_challenge", String.class)), DigestUtils.sha256(codeVerifier))){
            log.warning("The code verifier doesn't match the code challenge!");
            throw new NotAuthorizedException(UNAUTHORIZED.getReasonPhrase());
        }

        return clientAuthRepository.isClientIdAndSecretAllowed(clientId, clientSecret);
    }
}
