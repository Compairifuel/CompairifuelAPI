package org.compairifuel.compairifuelapi.authorization.service;

import io.jsonwebtoken.Claims;
import jakarta.ws.rs.NotAuthorizedException;
import org.apache.commons.codec.digest.DigestUtils;
import org.compairifuel.compairifuelapi.authorization.dataaccess.IAuthClientRepository;
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

import static org.mockito.Mockito.when;

class AuthorizationServiceImplTest {

    @InjectMocks
    private AuthorizationServiceImpl sut;

    @Mock
    private AuthCodeValidatorServiceImpl authCodeValidatorService;

    @Mock
    private IAuthClientRepository clientAuthRepository;

    @Mock
    private Claims claims;

    private AutoCloseable closeable;

    private AccessTokenDomain accessTokenDomain;

    @BeforeEach
    void setUp() {
        closeable = MockitoAnnotations.openMocks(this);
        accessTokenDomain = new AccessTokenDomain();
    }

    @Test
    void getAccessCodeReturnsAccessCodeWhenValidParams() {
        //arrange
        String grantType = "authorization_code";
        String authorizationCode = "authorization_code";
        String redirectUri = "https://example.com/callback";
        String jwtToken = "JwtToken";
        String clientId = "client_id";
        String clientSecret = "dummy_secret";
        String codeVerifier = "correct_code";
        String tokenType = "bearer";
        String codeChallenge = "correct_code";
        long expiresIn = 3600000L;

        accessTokenDomain.setAccessToken(jwtToken);
        accessTokenDomain.setExpiresIn(expiresIn);
        accessTokenDomain.setTokenType(tokenType);
        accessTokenDomain.setRefreshToken(jwtToken);

        byte[] hashedCodeChallenge = DigestUtils.sha256(codeChallenge);
        String encodedChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(hashedCodeChallenge);

        when(authCodeValidatorService.getExpiresIn()).thenReturn(expiresIn);
        when(authCodeValidatorService.createJwtsToken(Mockito.any(), Mockito.any(Date.class), Mockito.any(Date.class), Mockito.any(), Mockito.any())).thenReturn(jwtToken);
        when(authCodeValidatorService.retrieveJwtsClaims(authorizationCode, "CompairifuelAPI", java.util.List.of())).thenReturn(claims);
        when(authCodeValidatorService.getTokenType()).thenReturn(tokenType);

        when(clientAuthRepository.isRedirectUriAllowed(clientId, clientSecret, redirectUri)).thenReturn(true);
        when(clientAuthRepository.isClientIdAndSecretAllowed(clientId, clientSecret)).thenReturn(true);

        when(claims.get("code_challenge", String.class)).thenReturn(encodedChallenge);
        when(claims.get("redirect_uri", String.class)).thenReturn(redirectUri);
        when(claims.get("client_id", String.class)).thenReturn(clientId);
        when(claims.getSubject()).thenReturn("client_id");
        when(claims.getIssuer()).thenReturn("Compairifuel");

        //act
        AccessTokenDomain actual = sut.getAccessToken(grantType, authorizationCode, redirectUri, clientId, clientSecret, codeVerifier);

        //assert
        Assertions.assertNotNull(actual);
        Assertions.assertEquals(accessTokenDomain, actual);
    }

    @Test
    void getAccessCodeThrowsExceptionWhenInvalidCodeChallenge() {
        //arrange
        String grantType = "authorization_code";
        String authorizationCode = "authorization_code";
        String redirectUri = "https://example.com/callback";
        String clientId = "client_id";
        String clientSecret = "dummy_secret";
        String codeVerifier = "correct_code";
        String codeChallenge = "wrong_code";

        byte[] hashedCodeChallenge = DigestUtils.sha256(codeChallenge);
        String encodedChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(hashedCodeChallenge);

        when(authCodeValidatorService.retrieveJwtsClaims(authorizationCode, "CompairifuelAPI", java.util.List.of())).thenReturn(claims);

        when(claims.get("code_challenge", String.class)).thenReturn(encodedChallenge);
        when(claims.get("redirect_uri", String.class)).thenReturn(redirectUri);
        when(claims.get("client_id", String.class)).thenReturn(clientId);

        //assert act
        Assertions.assertThrows(NotAuthorizedException.class, () -> sut.getAccessToken(grantType, authorizationCode, redirectUri, clientId, clientSecret, codeVerifier));

    }

    @Test
    void getAccessCodeThrowsExceptionWhenInvalidRedirectUri() {
        //arrange
        String grantType = "authorization_code";
        String authorizationCode = "authorization_code";
        String redirectUri = "https://example.com/callback";
        String clientId = "client_id";
        String clientSecret = "dummy_secret";
        String codeVerifier = "correct_code";
        String codeChallenge = "correct_code";
        byte[] hashedCodeChallenge = DigestUtils.sha256(codeChallenge);
        String encodedChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(hashedCodeChallenge);

        when(authCodeValidatorService.retrieveJwtsClaims(authorizationCode, "CompairifuelAPI", java.util.List.of())).thenReturn(claims);

        when(claims.get("code_challenge", String.class)).thenReturn(encodedChallenge);
        when(claims.get("client_id", String.class)).thenReturn(clientId);

        //assert act
        Assertions.assertThrows(NotAuthorizedException.class, () -> sut.getAccessToken(grantType, authorizationCode, redirectUri, clientId, clientSecret, codeVerifier));

    }

    @Test
    void getAccessCodeThrowsExceptionWhenInvalidClientId() {
        //arrange
        String grantType = "authorization_code";
        String authorizationCode = "authorization_code";
        String redirectUri = "https://example.com/callback";
        String clientId = "client_id";
        String clientSecret = "dummy_secret";
        String codeVerifier = "correct_code";
        String codeChallenge = "correct_code";

        byte[] hashedCodeChallenge = DigestUtils.sha256(codeChallenge);
        String encodedChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(hashedCodeChallenge);

        when(authCodeValidatorService.retrieveJwtsClaims(authorizationCode, "CompairifuelAPI", java.util.List.of())).thenReturn(claims);

        when(claims.get("code_challenge", String.class)).thenReturn(encodedChallenge);
        when(claims.get("redirect_uri", String.class)).thenReturn(redirectUri);

        //assert act
        Assertions.assertThrows(NotAuthorizedException.class, () -> sut.getAccessToken(grantType, authorizationCode, redirectUri, clientId, clientSecret, codeVerifier));

    }

    @Test
    void getAccessTokenByRefreshTokenReturnsWhenValidParams() {
        //Arrange
        String grantType = "authorization_code";
        String redirectUri = "https://example.com/callback";
        String jwtToken = "JwtToken";
        String clientId = "client_id";
        String clientSecret = "dummy_secret";
        String codeVerifier = "correct_code";
        String tokenType = "bearer";
        String codeChallenge = "correct_code";
        String refreshToken = "refresh_token";
        long expiresIn = 3600000L;

        accessTokenDomain.setAccessToken(jwtToken);
        accessTokenDomain.setExpiresIn(expiresIn);
        accessTokenDomain.setTokenType(tokenType);
        accessTokenDomain.setRefreshToken(jwtToken);
        byte[] hashedCodeChallenge = DigestUtils.sha256(codeChallenge);
        String encodedChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(hashedCodeChallenge);
        when(authCodeValidatorService.getExpiresIn()).thenReturn(expiresIn);
        when(authCodeValidatorService.createJwtsToken(Mockito.any(), Mockito.any(Date.class), Mockito.any(Date.class), Mockito.any(), Mockito.any())).thenReturn(jwtToken);
        when(authCodeValidatorService.retrieveJwtsClaims(refreshToken, "CompairifuelAPI", java.util.List.of())).thenReturn(claims);
        when(authCodeValidatorService.getTokenType()).thenReturn(tokenType);
        when(clientAuthRepository.isRedirectUriAllowed(clientId, clientSecret, redirectUri)).thenReturn(true);
        when(clientAuthRepository.isClientIdAndSecretAllowed(clientId, clientSecret)).thenReturn(true);

        when(claims.get("code_challenge", String.class)).thenReturn(encodedChallenge);
        when(claims.get("redirect_uri", String.class)).thenReturn(redirectUri);
        when(claims.get("client_id", String.class)).thenReturn(clientId);
        when(claims.getExpiration()).thenReturn(new Date());
        when(claims.getSubject()).thenReturn("client_id");
        when(claims.getIssuer()).thenReturn("Compairifuel");

        //act
        AccessTokenDomain actual = sut.getAccessTokenByRefreshToken(grantType, refreshToken, clientId, clientSecret, codeVerifier);

        //assert
        Assertions.assertNotNull(actual);
        Assertions.assertEquals(accessTokenDomain, actual);

    }

    @Test
    void getAccessTokenByRefreshTokenThrowsExceptionWhenInvalidRefreshToken() {
        //arrange
        String grantType = "authorization_code";
        String clientId = "client_id";
        String clientSecret = "dummy_secret";
        String codeVerifier = "correct_code";
        String codeChallenge = "wrong_code";
        String refreshToken = "refresh_token";


        byte[] hashedCodeChallenge = DigestUtils.sha256(codeChallenge);
        String encodedChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(hashedCodeChallenge);

        when(authCodeValidatorService.retrieveJwtsClaims(refreshToken, "CompairifuelAPI", java.util.List.of())).thenReturn(claims);

        when(claims.get("code_challenge", String.class)).thenReturn(encodedChallenge);
        when(claims.get("client_id", String.class)).thenReturn(clientId);

        //assert act
        Assertions.assertThrows(NotAuthorizedException.class, () -> sut.getAccessTokenByRefreshToken(grantType, refreshToken, clientId, clientSecret, codeVerifier));

    }

    @Test
    void getAccessTokenByRefreshTokenThrowsExceptionWhenInvalidClientId() {
        //arrange
        String grantType = "authorization_code";
        String clientId = "client_id";
        String clientSecret = "dummy_secret";
        String codeVerifier = "correct_code";
        String codeChallenge = "correct_code";
        String refreshToken = "refresh_token";

        byte[] hashedCodeChallenge = DigestUtils.sha256(codeChallenge);
        String encodedChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(hashedCodeChallenge);

        when(authCodeValidatorService.retrieveJwtsClaims(refreshToken, "CompairifuelAPI", java.util.List.of())).thenReturn(claims);

        when(claims.get("code_challenge", String.class)).thenReturn(encodedChallenge);

        //assert act
        Assertions.assertThrows(NotAuthorizedException.class, () -> sut.getAccessTokenByRefreshToken(grantType, refreshToken, clientId, clientSecret, codeVerifier));
    }


    @AfterEach
    void tearDown() throws Exception {
        closeable.close();
    }

}
