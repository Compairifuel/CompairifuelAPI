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
import java.io.IOException;

class HardcodedAuthClientRepositoryImplTest {
    private final HardcodedAuthClientRepositoryImpl sut = new HardcodedAuthClientRepositoryImpl() {
        @Override
        protected InputStream openResource() {
                    String yaml = """
        - clientId: client-1
          clientSecret: null
          enabled: true
          redirectUris:
            - "myapp://auth/back"
            - "http://domain.org/callback"
          roles: []

        - clientId: client-2
          clientSecret: "bqVfA3MYw28d7Rd4Tu375dbdTIuv9L_mK5ZTUBgogOs="
          enabled: false
          redirectUris:
            - "https://website.example/authorized"
          roles: []

        - clientId: client-3
          clientSecret: "bqVfA3MYw28d7Rd4Tu375dbdTIuv9L_mK5ZTUBgogOs="
          enabled: true
          redirectUris:
            - "https://website.example/authorized"
          roles: []
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
        client1.clientSecret = null;
        client1.redirectUris = List.of("myapp://auth/back","http://domain.org/callback");
        client1.enabled = true;
        client1.roles = List.of();
        AuthClient client2 = new AuthClient();
        client2.clientId = "client-2";
        client2.clientSecret = "bqVfA3MYw28d7Rd4Tu375dbdTIuv9L_mK5ZTUBgogOs=";
        client2.redirectUris = List.of("https://website.example/authorized");
        client2.enabled = false;
        client2.roles = List.of();

        AuthClient client3 = new AuthClient();
        client3.clientId = "client-3";
        client3.clientSecret = "bqVfA3MYw28d7Rd4Tu375dbdTIuv9L_mK5ZTUBgogOs=";
        client3.redirectUris = List.of("https://website.example/authorized");
        client3.enabled = true;
        client3.roles = List.of();

        clients = List.of(client1, client2, client3);
    }

    @Test
    void ValidYamlButThrowsReturnsEmpty() throws Exception {
        // Arrange
        String clientId = "";
        String clientSecret = null;
        when(yamlLoader.load(any(BufferedReader.class), eq(AuthClient.class))).thenThrow(new IOException());

        // Act
        AuthClient result = sut.getClientByIdAndSecret(clientId,clientSecret);

        // Assert
        assertNull(result);
    }

    @Test
    void getClientById_returnsClient_whenClientExists() throws Exception {
        // Arrange
        String clientId = "client-1";
        String clientSecret = null;
        when(yamlLoader.load(any(BufferedReader.class), eq(AuthClient.class))).thenReturn(clients.stream());

        // Act
        AuthClient result = sut.getClientByIdAndSecret(clientId,clientSecret);

        // Assert
        assertNotNull(result);
        assertEquals(clientId, result.clientId);
    }

    @Test
    void getClientByIdReturnsNull() throws Exception {
        // Arrange
        String clientId = "";
        String clientSecret = null;
        when(yamlLoader.load(any(BufferedReader.class), eq(AuthClient.class))).thenReturn(clients.stream());

        // Act
        AuthClient result = sut.getClientByIdAndSecret(clientId,clientSecret);

        // Assert
        assertNull(result);
    }

    @Test
    void NoYamlReturnsEmpty() {
        // Arrange
        String clientId = "";
        String clientSecret = null;
        HardcodedAuthClientRepositoryImpl sutNoResource = new HardcodedAuthClientRepositoryImpl() {
            @Override
            protected InputStream openResource() {
                return null;
            }
        };

        // Act
        AuthClient result = sutNoResource.getClientByIdAndSecret(clientId,clientSecret);

        // Assert
        assertNull(result);
    }

    @Test
    void isRedirectUriAllowed_returnsTrue_whenUriIsAllowed() throws Exception {
        // Arrange
        String clientId = "client-1";
        String clientSecret = null;
        String redirectUri = "myapp://auth/back";
        when(yamlLoader.load(any(BufferedReader.class), eq(AuthClient.class))).thenReturn(clients.stream());

        // Act
        boolean allowed = sut.isRedirectUriAllowed(
                clientId,
                clientSecret,
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
        String clientSecret = null;
        when(yamlLoader.load(any(BufferedReader.class), eq(AuthClient.class))).thenReturn(clients.stream());

        // Act
        boolean allowed = sut.isRedirectUriAllowed(
                clientId,
                clientSecret,
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
        String clientSecret = "e526b1b1b138484d747f63d55658ce41c4c084341afe4556a790243045eb96292f13de9e5407ac21b7e87a565c7d71dac5ef102fa1c004843f5ccaf4f3dffef26b38d7a1184d187e1fd20275784484850b861eea74342459726854c163e01010e091c1964aa89d01395948dd18aaf44e5944f4771d05e696161e42e8551a49e5cd863e880c17eace5f8847a069ce71aefe947678f749457961037e6d70804747f31517618fb791b5518a69a9d20b35c7561b3653e5cbb870a4588f380cf53b6285647d5c46a2bb27cc4a1a34332223cc6f8dbd728a360e853665ba5df9112e68f95074065121292cb4d5c95a9630e4ff6142a7f335c88cbe9b2b089f7c4e470e";
        when(yamlLoader.load(any(BufferedReader.class), eq(AuthClient.class))).thenReturn(clients.stream());

        // Act
        boolean allowed = sut.isRedirectUriAllowed(
                clientId,
                clientSecret,
                redirectUri
        );

        // Assert
        assertFalse(allowed);
    }

    @Test
    void isRedirectUriAllowed_returnsFalse_whenClientSecretIsNotNull() throws Exception {
        // Arrange
        String clientId = "client-1";
        String redirectUri = "myapp://auth/back";
        String clientSecret = "incorrect-secret";
        when(yamlLoader.load(any(BufferedReader.class), eq(AuthClient.class))).thenReturn(clients.stream());

        // Act
        boolean allowed = sut.isRedirectUriAllowed(
                clientId,
                clientSecret,
                redirectUri
        );

        // Assert
        assertFalse(allowed);
    }

    @Test
    void isRedirectUriAllowed_returnsFalse_whenClientSecretIsInvalid() throws Exception {
        // Arrange
        String clientId = "client-3";
        String redirectUri = "https://website.example/authorized";
        String clientSecret = "incorrect-secret";
        when(yamlLoader.load(any(BufferedReader.class), eq(AuthClient.class))).thenReturn(clients.stream());

        // Act
        boolean allowed = sut.isRedirectUriAllowed(
                clientId,
                clientSecret,
                redirectUri
        );

        // Assert
        assertFalse(allowed);
    }

    @Test
    void isRedirectUriAllowed_returnsTrue_whenClientSecretIsValid() throws Exception {
        // Arrange
        String clientId = "client-3";
        String redirectUri = "https://website.example/authorized";
        String clientSecret = "e526b1b1b138484d747f63d55658ce41c4c084341afe4556a790243045eb96292f13de9e5407ac21b7e87a565c7d71dac5ef102fa1c004843f5ccaf4f3dffef26b38d7a1184d187e1fd20275784484850b861eea74342459726854c163e01010e091c1964aa89d01395948dd18aaf44e5944f4771d05e696161e42e8551a49e5cd863e880c17eace5f8847a069ce71aefe947678f749457961037e6d70804747f31517618fb791b5518a69a9d20b35c7561b3653e5cbb870a4588f380cf53b6285647d5c46a2bb27cc4a1a34332223cc6f8dbd728a360e853665ba5df9112e68f95074065121292cb4d5c95a9630e4ff6142a7f335c88cbe9b2b089f7c4e470e";
        when(yamlLoader.load(any(BufferedReader.class), eq(AuthClient.class))).thenReturn(clients.stream());

        // Act
        boolean allowed = sut.isRedirectUriAllowed(
                clientId,
                clientSecret,
                redirectUri
        );

        // Assert
        assertTrue(allowed);
    }

    @Test
    void isClientIdAndSecretAllowed_returnsTrue_whenClientIdAndSecretAreValid() throws Exception {
        // Arrange
        String clientId = "client-3";
        String clientSecret = "e526b1b1b138484d747f63d55658ce41c4c084341afe4556a790243045eb96292f13de9e5407ac21b7e87a565c7d71dac5ef102fa1c004843f5ccaf4f3dffef26b38d7a1184d187e1fd20275784484850b861eea74342459726854c163e01010e091c1964aa89d01395948dd18aaf44e5944f4771d05e696161e42e8551a49e5cd863e880c17eace5f8847a069ce71aefe947678f749457961037e6d70804747f31517618fb791b5518a69a9d20b35c7561b3653e5cbb870a4588f380cf53b6285647d5c46a2bb27cc4a1a34332223cc6f8dbd728a360e853665ba5df9112e68f95074065121292cb4d5c95a9630e4ff6142a7f335c88cbe9b2b089f7c4e470e";
        when(yamlLoader.load(any(BufferedReader.class), eq(AuthClient.class))).thenReturn(clients.stream());

        // Act
        boolean allowed = sut.isClientIdAndSecretAllowed(
                clientId,
                clientSecret
        );

        // Assert
        assertTrue(allowed);
    }

    @Test
    void isClientIdAndSecretAllowed_returnsFalse_whenClientIdIsInvalid() throws Exception {
        // Arrange
        String clientId = "invalid-client-id";
        String clientSecret = "e526b1b1b138484d747f63d55658ce41c4c084341afe4556a790243045eb96292f13de9e5407ac21b7e87a565c7d71dac5ef102fa1c004843f5ccaf4f3dffef26b38d7a1184d187e1fd20275784484850b861eea74342459726854c163e01010e091c1964aa89d01395948dd18aaf44e5944f4771d05e696161e42e8551a49e5cd863e880c17eace5f8847a069ce71aefe947678f749457961037e6d70804747f31517618fb791b5518a69a9d20b35c7561b3653e5cbb870a4588f380cf53b6285647d5c46a2bb27cc4a1a34332223cc6f8dbd728a360e853665ba5df9112e68f95074065121292cb4d5c95a9630e4ff6142a7f335c88cbe9b2b089f7c4e470e";
        when(yamlLoader.load(any(BufferedReader.class), eq(AuthClient.class))).thenReturn(clients.stream());

        // Act
        boolean allowed = sut.isClientIdAndSecretAllowed(
                clientId,
                clientSecret
        );

        // Assert
        assertFalse(allowed);
    }

    @Test
    void getClientByIdAndSecretAndNotEnabledWhenRedirectUriIsInvalid_ReturnsTrue() throws Exception {
        // Arrange
        String clientId = "client-2";
        String clientSecret = "e526b1b1b138484d747f63d55658ce41c4c084341afe4556a790243045eb96292f13de9e5407ac21b7e87a565c7d71dac5ef102fa1c004843f5ccaf4f3dffef26b38d7a1184d187e1fd20275784484850b861eea74342459726854c163e01010e091c1964aa89d01395948dd18aaf44e5944f4771d05e696161e42e8551a49e5cd863e880c17eace5f8847a069ce71aefe947678f749457961037e6d70804747f31517618fb791b5518a69a9d20b35c7561b3653e5cbb870a4588f380cf53b6285647d5c46a2bb27cc4a1a34332223cc6f8dbd728a360e853665ba5df9112e68f95074065121292cb4d5c95a9630e4ff6142a7f335c88cbe9b2b089f7c4e470e";
        when(yamlLoader.load(any(BufferedReader.class), eq(AuthClient.class))).thenReturn(clients.stream());

        // Act
        AuthClient client = sut.getClientByIdAndSecret(
                clientId,
                clientSecret
        );

        // Arrange
        when(yamlLoader.load(any(BufferedReader.class), eq(AuthClient.class))).thenReturn(clients.stream());

        // Act
        boolean redirectUriAllowed = sut.isRedirectUriAllowed(
                clientId,
                clientSecret,
                "https://example.com/authorized"
        );

        // Assert
        assertNotNull(client);
        assertFalse(client.enabled);
        assertFalse(redirectUriAllowed);
    }
}