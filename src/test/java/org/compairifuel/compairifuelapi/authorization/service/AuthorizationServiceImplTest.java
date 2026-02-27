package org.compairifuel.compairifuelapi.authorization.service;

import io.jsonwebtoken.Claims;
import jakarta.ws.rs.ForbiddenException;
import org.apache.commons.codec.digest.DigestUtils;
import org.compairifuel.compairifuelapi.authorization.service.domain.AccessTokenDomain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import java.util.Base64;
import java.util.Date;
import java.util.HashMap;

import static org.mockito.Mockito.when;

class AuthorizationServiceImplTest {

    @InjectMocks
    private AuthorizationServiceImpl sut;

    @Mock
    private AuthCodeValidatorServiceImpl authCodeValidatorService;

    @Mock
    private Claims claims;

    private AutoCloseable closeable;

    private AccessTokenDomain accessTokenDomain;

    private String grantType = "authorization_code";
    private String authorizationCode = "authorization_code";
    private String redirectUri = "https://example.com/callback";
    private String jwtToken = "JwtToken";
    private String clientId = "client_id";
    private String codeVerifier = "correct_code";
    private String tokenType = "bearer";
    private String codeChallenge = "correct_code";
    private String refreshToken = "refresh_token";
    private long expiresIn = 3600000L;

    @BeforeEach
    void setUp() {
        closeable = MockitoAnnotations.openMocks(this);
        accessTokenDomain = new AccessTokenDomain();
    }

    @Test
    void getAccessCodeReturnsAccessCodeWhenValidParams() {
        //arrange

        accessTokenDomain.setAccessToken(jwtToken);
        accessTokenDomain.setExpiresIn(expiresIn);
        accessTokenDomain.setTokenType(tokenType);

        byte[] hashedCodeChallenge = DigestUtils.sha256(codeChallenge);
        String encodedChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(hashedCodeChallenge);

        when(authCodeValidatorService.getExpiresIn()).thenReturn(expiresIn);
        when(authCodeValidatorService.createJwtsToken(Mockito.eq(new HashMap<>()), Mockito.any(Date.class), Mockito.any(Date.class))).thenReturn(jwtToken);
        when(authCodeValidatorService.retrieveJwtsClaims(authorizationCode)).thenReturn(claims);
        when(authCodeValidatorService.getTokenType()).thenReturn(tokenType);

        when(claims.get("code_challenge", String.class)).thenReturn(encodedChallenge);
        when(claims.get("redirect_uri", String.class)).thenReturn(redirectUri);
        when(claims.get("client_id", String.class)).thenReturn(clientId);

        //act
        AccessTokenDomain actual = sut.getAccessToken(grantType, authorizationCode, redirectUri, clientId, codeVerifier);

        //assert
        Assertions.assertNotNull(actual);
        Assertions.assertEquals(accessTokenDomain, actual);
    }

    @Test
    void getAccessCodeThrowsExceptionWhenInvalidCodeChallenge() {
        //arrange
        codeChallenge = "wrong_code";

        byte[] hashedCodeChallenge = DigestUtils.sha256(codeChallenge);
        String encodedChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(hashedCodeChallenge);

        when(authCodeValidatorService.retrieveJwtsClaims(authorizationCode)).thenReturn(claims);

        when(claims.get("code_challenge", String.class)).thenReturn(encodedChallenge);
        when(claims.get("redirect_uri", String.class)).thenReturn(redirectUri);
        when(claims.get("client_id", String.class)).thenReturn(clientId);


        //assert act
        Assertions.assertThrows(ForbiddenException.class, () -> sut.getAccessToken(grantType, authorizationCode, redirectUri, clientId, codeVerifier));

    }

    @Test
    void getAccessCodeThrowsExceptionWhenInvalidRedirectUri() {
        //arrange
        byte[] hashedCodeChallenge = DigestUtils.sha256(codeChallenge);
        String encodedChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(hashedCodeChallenge);

        when(authCodeValidatorService.retrieveJwtsClaims(authorizationCode)).thenReturn(claims);

        when(claims.get("code_challenge", String.class)).thenReturn(encodedChallenge);
        when(claims.get("client_id", String.class)).thenReturn(clientId);



        //assert act
        Assertions.assertThrows(ForbiddenException.class, () -> sut.getAccessToken(grantType, authorizationCode, redirectUri, clientId, codeVerifier));

    }

    @Test
    void getAccessCodeThrowsExceptionWhenInvalidClientId() {
        //arrange
        byte[] hashedCodeChallenge = DigestUtils.sha256(codeChallenge);
        String encodedChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(hashedCodeChallenge);

        when(authCodeValidatorService.retrieveJwtsClaims(authorizationCode)).thenReturn(claims);

        when(claims.get("code_challenge", String.class)).thenReturn(encodedChallenge);
        when(claims.get("redirect_uri", String.class)).thenReturn(redirectUri);


        //assert act
        Assertions.assertThrows(ForbiddenException.class, () -> sut.getAccessToken(grantType, authorizationCode, redirectUri, clientId, codeVerifier));

    }

    @Test
    void getAccessTokenByRefreshTokenReturnsWhenValidParams() {
        accessTokenDomain.setAccessToken(jwtToken);
        accessTokenDomain.setExpiresIn(expiresIn);
        accessTokenDomain.setTokenType(tokenType);
        byte[] hashedCodeChallenge = DigestUtils.sha256(codeChallenge);
        String encodedChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(hashedCodeChallenge);

        when(authCodeValidatorService.getExpiresIn()).thenReturn(expiresIn);
        when(authCodeValidatorService.createJwtsToken(Mockito.eq(new HashMap<>()), Mockito.any(Date.class), Mockito.any(Date.class))).thenReturn(jwtToken);
        when(authCodeValidatorService.retrieveJwtsClaims(refreshToken)).thenReturn(claims);
        when(authCodeValidatorService.getTokenType()).thenReturn(tokenType);

        when(claims.get("code_challenge", String.class)).thenReturn(encodedChallenge);
        when(claims.get("redirect_uri", String.class)).thenReturn(redirectUri);
        when(claims.get("client_id", String.class)).thenReturn(clientId);

        //act
        AccessTokenDomain actual = sut.getAccessTokenByRefreshToken(grantType,refreshToken, clientId, codeVerifier);

        //assert
        Assertions.assertNotNull(actual);
        Assertions.assertEquals(accessTokenDomain, actual);

    }

    @Test
    void getAccessTokenByRefreshTokenThrowsExceptionWhenInvalidRefreshToken() {
        //arrange
        codeChallenge = "wrong_code";

        byte[] hashedCodeChallenge = DigestUtils.sha256(codeChallenge);
        String encodedChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(hashedCodeChallenge);

        when(authCodeValidatorService.retrieveJwtsClaims(refreshToken)).thenReturn(claims);

        when(claims.get("code_challenge", String.class)).thenReturn(encodedChallenge);
        when(claims.get("client_id", String.class)).thenReturn(clientId);


        //assert act
        Assertions.assertThrows(ForbiddenException.class, () -> sut.getAccessTokenByRefreshToken(grantType,refreshToken, clientId, codeVerifier));

    }

    @Test
    void getAccessTokenByRefreshTokenThrowsExceptionWhenInvalidClientId() {

        byte[] hashedCodeChallenge = DigestUtils.sha256(codeChallenge);
        String encodedChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(hashedCodeChallenge);

        when(authCodeValidatorService.retrieveJwtsClaims(refreshToken)).thenReturn(claims);

        when(claims.get("code_challenge", String.class)).thenReturn(encodedChallenge);

        //assert act
        Assertions.assertThrows(ForbiddenException.class, () -> sut.getAccessTokenByRefreshToken(grantType,refreshToken, clientId, codeVerifier));

    }


    @AfterEach
    void tearDown() throws Exception {

        closeable.close();

    }

}
