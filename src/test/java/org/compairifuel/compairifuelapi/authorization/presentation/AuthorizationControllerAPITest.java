package org.compairifuel.compairifuelapi.authorization.presentation;

import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.*;
import org.compairifuel.compairifuelapi.authorization.service.IAuthorizationService;
import org.compairifuel.compairifuelapi.authorization.service.domain.AccessTokenDomain;
import org.compairifuel.compairifuelapi.utils.presentation.CacheControlDirectives;
import org.glassfish.hk2.utilities.binding.AbstractBinder;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.ClientProperties;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.test.JerseyTest;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@Tag("api-test")
class AuthorizationControllerAPITest extends JerseyTest {
    IAuthorizationService authorizationService = mock(IAuthorizationService.class);

    @Override
    protected Application configure() {
        return new ResourceConfig(AuthorizationController.class)
                .register(new AbstractBinder() {
                    @Override
                    protected void configure() {
                        bind(authorizationService).to(IAuthorizationService.class);
                    }
                });
    }

    @Override
    protected void configureClient(ClientConfig config) {
        config.property(ClientProperties.FOLLOW_REDIRECTS, false);
    }

    @DisplayName("GIVEN valid parameters WHEN getAuthorizationCode is called THEN it validates parameters without errors")
    @ParameterizedTest(name = "parameters: responseType={0}, clientId={1}, redirectUri={2}, codeChallenge={3}, state={4}, redirectToUri={5}")
    @MethodSource({
            "org.compairifuel.compairifuelapi.authorization.presentation.AuthorizationControllerAPIFixtures#provideValidRedirectURIGetAuthorizationCodeParameters",
            "org.compairifuel.compairifuelapi.authorization.presentation.AuthorizationControllerAPIFixtures#provideValidClientIdGetAuthorizationCodeParameters",
            "org.compairifuel.compairifuelapi.authorization.presentation.AuthorizationControllerAPIFixtures#provideValidCodeChallengeGetAuthorizationCodeParameters"
    })
    void testGetAuthorizationCodeValidatesParametersWithoutErrors(String responseType, String clientId, String redirectUri, String codeChallenge, String state, URI redirectToURI) {
        when(authorizationService.getAuthorizationCode(responseType, clientId, redirectUri, codeChallenge, "{}"))
                .thenReturn(redirectToURI);

        Response response = target("/oauth")
                .queryParam("response_type", responseType)
                .queryParam("client_id", clientId)
                .queryParam("redirect_uri", redirectUri)
                .queryParam("code_challenge", codeChallenge)
                .queryParam("state", state)
                .request(MediaType.APPLICATION_JSON)
                .get();

        assertEquals(Response.Status.SEE_OTHER.getStatusCode(), response.getStatus(), "Response code should be 303 See Other");
        assertEquals(redirectToURI, response.getLocation());
        assertTrue(response.getHeaders().containsKey(HttpHeaders.CACHE_CONTROL), "Response should contain Cache-Control header");
        assertEquals(1, response.getHeaders().get(HttpHeaders.CACHE_CONTROL).size(), "Cache-Control header should have one value");
        assertEquals(CacheControlDirectives.NO_STORE, response.getHeaders().get(HttpHeaders.CACHE_CONTROL).get(0));
    }

    @DisplayName("GIVEN invalid parameters WHEN getAuthorizationCode is called THEN response is 400")
    @ParameterizedTest(name = "parameters: responseType={0}, clientId={1}, redirectUri={2}, codeChallenge={3}, state={4}")
    @MethodSource("org.compairifuel.compairifuelapi.authorization.presentation.AuthorizationControllerAPIFixtures#provideInvalidRedirectURIGetAuthorizationCodeParameters")
    void testGetAuthorizationCodeValidatesParametersWithErrors(String responseType, String clientId, String redirectUri, String codeChallenge, String state) {
        when(authorizationService.getAuthorizationCode(responseType, clientId, redirectUri, codeChallenge, state))
                .thenReturn(URI.create("http://localhost:8080?state=%7B&7D&code=123"));

        Response response = target("/oauth")
                .queryParam("response_type", responseType)
                .queryParam("client_id", clientId)
                .queryParam("redirect_uri", redirectUri)
                .queryParam("code_challenge", codeChallenge)
                .queryParam("state", state)
                .request(MediaType.APPLICATION_JSON)
                .get();

        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
    }

    @DisplayName("GIVEN valid parameters WHEN getAccessToken is called THEN it validates parameters without errors")
    @ParameterizedTest(name = "parameters: grantType={0}, code={1}, redirectUri={2}, clientId={3}, codeVerifier={4}")
    @MethodSource("org.compairifuel.compairifuelapi.authorization.presentation.AuthorizationControllerAPIFixtures#provideValidRedirectURIGetAccessTokenParameters")
    void testGetAccessTokenValidatesParametersWithoutErrors(String grantType, String code, String redirectUri, String clientId, String codeVerifier) {
        when(authorizationService.getAccessToken(grantType, code, redirectUri, clientId, codeVerifier))
                .thenReturn(new AccessTokenDomain());

        try (
            Response response = target("/oauth/token")
                .request(MediaType.APPLICATION_JSON)
                .post(Entity.form(
                        new Form()
                                .param("grant_type", grantType)
                                .param("code", code)
                                .param("redirect_uri", redirectUri)
                                .param("client_id", clientId)
                                .param("code_verifier", codeVerifier)
                ))
        ) {
            assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
            assertTrue(response.getHeaders().containsKey(HttpHeaders.CACHE_CONTROL), "Response should contain Cache-Control header");
            assertEquals(1, response.getHeaders().get(HttpHeaders.CACHE_CONTROL).size(), "Cache-Control header should have one value");
            assertEquals(CacheControlDirectives.NO_STORE, response.getHeaders().get(HttpHeaders.CACHE_CONTROL).get(0));
        }
    }

    @DisplayName("GIVEN invalid parameters WHEN getAccessToken is called THEN response is 400")
    @ParameterizedTest(name = "parameters: grantType={0}, code={1}, redirectUri={2}, clientId={3}, codeVerifier={4}")
    @MethodSource("org.compairifuel.compairifuelapi.authorization.presentation.AuthorizationControllerAPIFixtures#provideInvalidRedirectURIGetAccessTokenParameters")
    void testGetAccessTokenValidatesParametersWithErrors(String grantType, String code, String redirectUri, String clientId, String codeVerifier) {
        when(authorizationService.getAccessToken(grantType, code, redirectUri, clientId, codeVerifier))
                .thenReturn(new AccessTokenDomain());

        try (
            Response response = target("/oauth/token")
                    .request(MediaType.APPLICATION_JSON)
                    .post(Entity.form(
                            new Form()
                                    .param("grant_type", grantType)
                                    .param("code", code)
                                    .param("redirect_uri", redirectUri)
                                    .param("client_id", clientId)
                                    .param("code_verifier", codeVerifier
                    )))
        ) {
            assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
        }
    }
}
