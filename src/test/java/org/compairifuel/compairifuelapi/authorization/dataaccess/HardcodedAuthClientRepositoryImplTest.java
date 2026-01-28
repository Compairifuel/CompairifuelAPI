package org.compairifuel.compairifuelapi.authorization.dataaccess;

import org.compairifuel.compairifuelapi.utils.IYamlLoader;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;

import java.nio.charset.StandardCharsets;
import java.io.ByteArrayInputStream;

class HardcodedAuthClientRepositoryImplTest {
    private final HardcodedAuthClientRepositoryImpl sut = new HardcodedAuthClientRepositoryImpl() {
        @Override
        protected InputStream openResource() {
                    String yaml = """
        - clientId: client-1
          enabled: true
          redirectUris:
            - "myapp://auth/back"
            - "http://domain.org/callback"

        - clientId: client-2
          enabled: false
          redirectUris:
            - "https://website.example/authorized"
        """;
            return new ByteArrayInputStream(yaml.getBytes(StandardCharsets.UTF_8));
        }
    };
    private IYamlLoader yamlLoader;
    private List<AuthClient> clients;

    @BeforeEach
    void setUp() {
        yamlLoader = mock(IYamlLoader.class);

        sut.setYamlLoader(yamlLoader);

        AuthClient client1 = new AuthClient();
        client1.clientId = "client-1";
        client1.redirectUris = List.of("myapp://auth/back","http://domain.org/callback");
        client1.enabled = true;

        AuthClient client2 = new AuthClient();
        client2.clientId = "client-2";
        client2.redirectUris = List.of("https://website.example/authorized");
        client2.enabled = false;

        clients = List.of(client1, client2);
    }

    @Test
    void getClientById_returnsClient_whenClientExists() throws Exception {
        // Arrange
        String clientId = "client-1";
        when(yamlLoader.load(any(BufferedReader.class), eq(AuthClient.class))).thenReturn(clients.stream());

        // Act
        AuthClient result = sut.getClientById(clientId);

        // Assert
        assertNotNull(result);
        assertEquals(clientId, result.clientId);
    }

    @Test
    void getClientByIdReturnsNull() throws Exception {
        // Arrange
        String clientId = "";
        when(yamlLoader.load(any(BufferedReader.class), eq(AuthClient.class))).thenReturn(clients.stream());

        // Act
        AuthClient result = sut.getClientById(clientId);

        // Assert
        assertNull(result);
    }

    @Test
    void NoYamlReturnsEmpty() {
        // Arrange
        String clientId = "";
        HardcodedAuthClientRepositoryImpl sutNoResource = new HardcodedAuthClientRepositoryImpl() {
            @Override
            protected InputStream openResource() {
                return null;
            }
        };

        // Act
        AuthClient result = sutNoResource.getClientById(clientId);

        // Assert
        assertNull(result);
    }

    @Test
    void isRedirectUriAllowed_returnsTrue_whenUriIsAllowed() throws Exception {
        // Arrange
        String clientId = "client-1";
        String redirectUri = "myapp://auth/back";
        when(yamlLoader.load(any(BufferedReader.class), eq(AuthClient.class))).thenReturn(clients.stream());

        // Act
        boolean allowed = sut.isRedirectUriAllowed(
                clientId,
                redirectUri
        );

        // Assert
        assertTrue(allowed);
    }

    @Test
    void isRedirectUriAllowed_returnsFalse_whenUriIsNotFound() throws Exception {
        // Arrange
        String clientId = "client-1";
        String redirectUri = "";
        when(yamlLoader.load(any(BufferedReader.class), eq(AuthClient.class))).thenReturn(clients.stream());

        // Act
        boolean allowed = sut.isRedirectUriAllowed(
                clientId,
                redirectUri
        );

        // Assert
        assertFalse(allowed);
    }

    @Test
    void isRedirectUriAllowed_returnsFalse_whenClientIsDisabled() throws Exception {
        // Arrange
        String clientId = "client-2";
        String redirectUri = "https://website.example/authorized";
        when(yamlLoader.load(any(BufferedReader.class), eq(AuthClient.class))).thenReturn(clients.stream());

        // Act
        boolean allowed = sut.isRedirectUriAllowed(
                clientId,
                redirectUri
        );

        // Assert
        assertFalse(allowed);
    }

}