package org.compairifuel.compairifuelapi.authorization.service;

import io.jsonwebtoken.Claims;
import jakarta.enterprise.inject.Default;
import jakarta.inject.Inject;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.InternalServerErrorException;
import jakarta.ws.rs.core.UriBuilder;
import lombok.Cleanup;
import lombok.extern.java.Log;
import org.apache.commons.codec.digest.DigestUtils;
import org.compairifuel.compairifuelapi.authorization.service.domain.AccessTokenDomain;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URI;
import java.util.*;

@Log(topic = "AuthorizationServiceImpl")
@Default
public class AuthorizationServiceImpl implements IAuthorizationService {
    private AuthCodeValidatorServiceImpl authCodeValidatorService;

    @Inject
    public void setAuthCodeValidatorService(AuthCodeValidatorServiceImpl authCodeValidatorService) {
        this.authCodeValidatorService = authCodeValidatorService;
    }

    @Override
    public URI getAuthorizationCode(String grantType, String clientId, String redirectUri, String codeChallenge, String state) {
        UriBuilder redirectToURI = UriBuilder.fromUri(redirectUri);

        boolean isWhitelisted;
        try {
            @Cleanup BufferedReader br_uri = new BufferedReader(new InputStreamReader(Objects.requireNonNull(getClass().getClassLoader().getResourceAsStream("whitelisted_uri.yml"))));
            @Cleanup BufferedReader br_client = new BufferedReader(new InputStreamReader(Objects.requireNonNull(getClass().getClassLoader().getResourceAsStream("whitelisted_client.yml"))));
            isWhitelisted = br_uri.lines().anyMatch(el -> Objects.equals(UriBuilder.fromUri(el).replaceQuery("").build().toString(), redirectToURI.clone().replaceQuery("").build().toString())) &&
                    br_client.lines().anyMatch(el -> Objects.equals(el, clientId));
        } catch (Exception e) {
            throw new InternalServerErrorException(e.getMessage());
        }

        if (!isWhitelisted) {
            log.warning("The consumer isn't whitelisted!");
            throw new ForbiddenException();
        }

        long expiresIn = 36000;

        var hashMap = new HashMap<String, Object>();
        hashMap.put("state", state);
        hashMap.put("code_challenge", codeChallenge);
        hashMap.put("redirect_uri", redirectUri);
        hashMap.put("client_id", clientId);
        hashMap.put("grant_type", grantType);
        String authorizationCode = authCodeValidatorService.createJwtsToken(hashMap, new Date(System.currentTimeMillis() + expiresIn), new Date(System.currentTimeMillis()));

        return redirectToURI
                .queryParam("state", state)
                .queryParam("code", authorizationCode)
                .build();
    }

    @Override
    public AccessTokenDomain getAccessToken(String grantType, String authorizationCode, String redirectUri, String clientId, String codeVerifier) {
        Claims claims = authCodeValidatorService.retrieveJwtsClaims(authorizationCode);

        if (!Arrays.equals(Base64.getUrlDecoder().decode(claims.get("code_challenge", String.class)), DigestUtils.sha256(codeVerifier)) ||
                !redirectUri.equals(claims.get("redirect_uri", String.class)) ||
                !clientId.equals(claims.get("client_id", String.class))
        ) {
            log.warning("The consumer is not authorized!");
            throw new ForbiddenException();
        }

        return createAndBuildAccessTokenDomain(claims, clientId);
    }

    @Override
    public AccessTokenDomain getAccessTokenByRefreshToken(String grantType, String refreshToken, String clientId, String codeVerifier) {
        Claims claims = authCodeValidatorService.retrieveJwtsClaims(refreshToken);

        if (!Arrays.equals(Base64.getUrlDecoder().decode(claims.get("code_challenge", String.class)), DigestUtils.sha256(codeVerifier)) ||
                !clientId.equals(claims.get("client_id", String.class))
        ) {
            log.warning("The consumer is not authorized!");
            throw new ForbiddenException();
        }

        return createAndBuildAccessTokenDomain(claims, clientId);
    }

    private AccessTokenDomain createAndBuildAccessTokenDomain(Claims claims, String clientId) {
        String accessToken = authCodeValidatorService.createJwtsToken(new HashMap<>(), new Date(System.currentTimeMillis() + authCodeValidatorService.getExpiresIn()), new Date(System.currentTimeMillis()));

        HashMap<String, Object> refreshTokenMap = new HashMap<>();
        refreshTokenMap.put("code_challenge", claims.get("code_challenge", String.class));
        refreshTokenMap.put("client_id", clientId);
        String refreshToken = authCodeValidatorService.createJwtsToken(refreshTokenMap, new Date(System.currentTimeMillis() + (authCodeValidatorService.getExpiresIn() * 2)), new Date(System.currentTimeMillis()));

        AccessTokenDomain accessTokenDomain = new AccessTokenDomain();
        accessTokenDomain.setAccessToken(accessToken);
        accessTokenDomain.setExpiresIn(authCodeValidatorService.getExpiresIn());
        accessTokenDomain.setTokenType(authCodeValidatorService.getTokenType());
        accessTokenDomain.setRefreshToken(refreshToken);
        return accessTokenDomain;
    }
}
