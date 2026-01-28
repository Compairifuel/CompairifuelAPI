package org.compairifuel.compairifuelapi.utils;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import java.io.BufferedReader;
import java.io.StringReader;
import java.util.List;
import java.util.stream.Stream;
import org.compairifuel.compairifuelapi.authorization.dataaccess.*;

import static org.junit.jupiter.api.Assertions.*;

class IYamlLoaderTest  {
    private final IYamlLoader sut = new YamlLoaderImpl();
    private static BufferedReader reader;

    @BeforeAll
    static void setupAll() {
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

        reader = new BufferedReader(new StringReader(yaml));
    }

    @Test
    void load_readsYamlIntoObjects() throws Exception {
        List<AuthClient> clients = sut.load(reader, AuthClient.class).toList();

        assertEquals(2, clients.size());
        AuthClient client = clients.get(0);

        assertEquals("client-1", client.clientId);
        assertTrue(client.enabled);
        assertEquals(
                List.of("myapp://auth/back","http://domain.org/callback"),
                client.redirectUris
        );
    }

    @Test
    void load_readsYamlIntoObjects_andCorrectlyCloses() {
        String yaml = """
        - clientId: client-1
          enabled: true
          redirectUris:
            - "myapp://auth/back"
        """;

        BufferedReader readerNew = new BufferedReader(new StringReader(yaml));

        assertDoesNotThrow(()->{
            Stream<AuthClient> clients = sut.load(readerNew, AuthClient.class);

            clients.close();
        });
    }
}
