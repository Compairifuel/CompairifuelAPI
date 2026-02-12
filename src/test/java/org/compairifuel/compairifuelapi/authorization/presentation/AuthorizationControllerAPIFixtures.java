package org.compairifuel.compairifuelapi.authorization.presentation;

import jakarta.ws.rs.core.UriBuilder;
import org.junit.jupiter.params.provider.Arguments;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

@SuppressWarnings("unused") // Used by parameterized tests in AuthorizationControllerAPITest
class AuthorizationControllerAPIFixtures {
    static Stream<Arguments> provideValidRedirectURIGetAuthorizationCodeParameters() {
        return generateValidRedirectURIs().stream()
                .map(uri -> Arguments.of(
                        "code",
                        "6779ef20e75817b79602",
                        "e526b1b1b138484d747f63d55658ce41c4c084341afe4556a790243045eb96292f13de9e5407ac21b7e87a565c7d71dac5ef102fa1c004843f5ccaf4f3dffef26b38d7a1184d187e1fd20275784484850b861eea74342459726854c163e01010e091c1964aa89d01395948dd18aaf44e5944f4771d05e696161e42e8551a49e5cd863e880c17eace5f8847a069ce71aefe947678f749457961037e6d70804747f31517618fb791b5518a69a9d20b35c7561b3653e5cbb870a4588f380cf53b6285647d5c46a2bb27cc4a1a34332223cc6f8dbd728a360e853665ba5df9112e68f95074065121292cb4d5c95a9630e4ff6142a7f335c88cbe9b2b089f7c4e470e",
                        uri.toString(),
                        "pjGXfmpx1LUHqbxEB2KhEp5QXEA0XA5imOTeefSmmzI",
                        "%7B%7D",
                        "",
                        UriBuilder.fromUri(uri)
                            .queryParam("state", "%7B%7D")
                            .queryParam("code", "123")
                            .build()
                ));
    }

    static Stream<Arguments> provideValidClientIdGetAuthorizationCodeParameters() {
        List<String> clientIds = List.of(
                "ZYDPLLBWSK3MVQJSIYHB1OR2JXCY0X2C5UJ2QAR2MAAIT5Q",
                "6779ef20e75817b79602",
                "292085223830.apps.example.com",
                "f2a1ed52710d4533bde25be6da03b6e3",
                "269d98e4922fb3895e9ae2108cbb5064",
                "00000000400ECB04",
                "0oa2hl2inow5Uqc6c357"
        );
        return clientIds.stream()
                .map(clientId -> Arguments.of(
                        "code",
                        clientId,
                        "e526b1b1b138484d747f63d55658ce41c4c084341afe4556a790243045eb96292f13de9e5407ac21b7e87a565c7d71dac5ef102fa1c004843f5ccaf4f3dffef26b38d7a1184d187e1fd20275784484850b861eea74342459726854c163e01010e091c1964aa89d01395948dd18aaf44e5944f4771d05e696161e42e8551a49e5cd863e880c17eace5f8847a069ce71aefe947678f749457961037e6d70804747f31517618fb791b5518a69a9d20b35c7561b3653e5cbb870a4588f380cf53b6285647d5c46a2bb27cc4a1a34332223cc6f8dbd728a360e853665ba5df9112e68f95074065121292cb4d5c95a9630e4ff6142a7f335c88cbe9b2b089f7c4e470e",
                        "http://localhost:8080",
                        "pjGXfmpx1LUHqbxEB2KhEp5QXEA0XA5imOTeefSmmzI",
                        "%7B%7D",
                        "admin customer",
                        "http://localhost:8080?state=%7B%7D&code=123"
                ));
    }

    static Stream<Arguments> provideValidCodeChallengeGetAuthorizationCodeParameters() {
        List<String> codeChallenges = List.of(
            "pjGXfmpx1LUHqbxEB2KhEp5QXEA0XA5imOTeefSmmzI",
            "NDc0ZWQ5M2MwYTgwZGVhZGU4NWU4ODgwNDNhOThjYmQwNTk1ZjA3YzdlMjlhZTIwYTQwMDg3MDFkZDQ2YjNhZQ",
            "YThkODY3OWM4Y2U2ZDAxMTZmNGZkYjAyZjUzMjJkMjkyNjg3NzBhMjhmMWNmMzUyYTY1NzJhNDUxMjU5ZTMxMQ"
        );
        return codeChallenges.stream()
                .map(codeChallenge -> Arguments.of(
                        "code",
                        "6779ef20e75817b79602",
                        "e526b1b1b138484d747f63d55658ce41c4c084341afe4556a790243045eb96292f13de9e5407ac21b7e87a565c7d71dac5ef102fa1c004843f5ccaf4f3dffef26b38d7a1184d187e1fd20275784484850b861eea74342459726854c163e01010e091c1964aa89d01395948dd18aaf44e5944f4771d05e696161e42e8551a49e5cd863e880c17eace5f8847a069ce71aefe947678f749457961037e6d70804747f31517618fb791b5518a69a9d20b35c7561b3653e5cbb870a4588f380cf53b6285647d5c46a2bb27cc4a1a34332223cc6f8dbd728a360e853665ba5df9112e68f95074065121292cb4d5c95a9630e4ff6142a7f335c88cbe9b2b089f7c4e470e",
                        "http://localhost:8080",
                        codeChallenge,
                        "%7B%7D",
                        "user:read",
                        "http://localhost:8080?state=%7B%7D&code=123"
                ));
    }

    static Stream<Arguments> provideInvalidRedirectURIGetAuthorizationCodeParameters() {
        return generateInvalidRedirectURIs().stream()
                .map(uri -> Arguments.of(
                        "code",
                        "6779ef20e75817b79602",
                        "e526b1b1b138484d747f63d55658ce41c4c084341afe4556a790243045eb96292f13de9e5407ac21b7e87a565c7d71dac5ef102fa1c004843f5ccaf4f3dffef26b38d7a1184d187e1fd20275784484850b861eea74342459726854c163e01010e091c1964aa89d01395948dd18aaf44e5944f4771d05e696161e42e8551a49e5cd863e880c17eace5f8847a069ce71aefe947678f749457961037e6d70804747f31517618fb791b5518a69a9d20b35c7561b3653e5cbb870a4588f380cf53b6285647d5c46a2bb27cc4a1a34332223cc6f8dbd728a360e853665ba5df9112e68f95074065121292cb4d5c95a9630e4ff6142a7f335c88cbe9b2b089f7c4e470e",
                        uri,
                        "pjGXfmpx1LUHqbxEB2KhEp5QXEA0XA5imOTeefSmmzI",
                        "%7B%7D",
                        "admin:read user:profile:write customer"
                ));
    }

    static Stream<Arguments> provideValidRedirectURIGetAccessTokenParameters() {
        return generateValidRedirectURIs().stream()
                .map(uri -> Arguments.of(
                        "authorization_code",
                        "6779ef20e75817b79602",
                        uri.toString(),
                        "6779ef20e75817b79602",
                        "e526b1b1b138484d747f63d55658ce41c4c084341afe4556a790243045eb96292f13de9e5407ac21b7e87a565c7d71dac5ef102fa1c004843f5ccaf4f3dffef26b38d7a1184d187e1fd20275784484850b861eea74342459726854c163e01010e091c1964aa89d01395948dd18aaf44e5944f4771d05e696161e42e8551a49e5cd863e880c17eace5f8847a069ce71aefe947678f749457961037e6d70804747f31517618fb791b5518a69a9d20b35c7561b3653e5cbb870a4588f380cf53b6285647d5c46a2bb27cc4a1a34332223cc6f8dbd728a360e853665ba5df9112e68f95074065121292cb4d5c95a9630e4ff6142a7f335c88cbe9b2b089f7c4e470e",
                        "S256CodeVerifierExample123!"
                ));
    }

    static Stream<Arguments> provideInvalidRedirectURIGetAccessTokenParameters() {
        return generateInvalidRedirectURIs().stream()
                .map(uri -> Arguments.of(
                        "authorization_code",
                        "6779ef20e75817b79602",
                        "e526b1b1b138484d747f63d55658ce41c4c084341afe4556a790243045eb96292f13de9e5407ac21b7e87a565c7d71dac5ef102fa1c004843f5ccaf4f3dffef26b38d7a1184d187e1fd20275784484850b861eea74342459726854c163e01010e091c1964aa89d01395948dd18aaf44e5944f4771d05e696161e42e8551a49e5cd863e880c17eace5f8847a069ce71aefe947678f749457961037e6d70804747f31517618fb791b5518a69a9d20b35c7561b3653e5cbb870a4588f380cf53b6285647d5c46a2bb27cc4a1a34332223cc6f8dbd728a360e853665ba5df9112e68f95074065121292cb4d5c95a9630e4ff6142a7f335c88cbe9b2b089f7c4e470e",
                        uri,
                        "6779ef20e75817b79602",
                        "S256CodeVerifierExample123!"
                ));
    }

    private static List<URI> generateValidRedirectURIs() {
        UriBuilder customSchemeBuilder = UriBuilder.newInstance()
                .scheme("myapp");
        UriBuilder exampleComBuilder = UriBuilder.newInstance()
                .host("example.com");
        List<UriBuilder> baseBuilders = List.of(
                customSchemeBuilder.clone()
                        .host("oauth"),
                exampleComBuilder.clone()
                        .scheme("http"),
                exampleComBuilder.clone()
                        .scheme("https"),
                UriBuilder.newInstance()
                        .scheme("http")
                        .host("localhost"),
                UriBuilder.newInstance()
                        .scheme("http")
                        .host("sub.example.com"),
                UriBuilder.newInstance()
                        .scheme("https")
                        .host("sub.example.com")
        );

        return baseBuilders.stream()
                .flatMap(uri -> Stream.of(
                        uri.clone(),
                        uri.clone().port(8080)
                ))
                .flatMap(uri -> Stream.of(
                        uri.clone(),
                        uri.clone().path("callback"),
                        uri.clone().path("oauth/callback"),
                        uri.clone().path("oauth/callback.php")
                ))
                .flatMap(uri -> Stream.of(
                        uri.clone(),
                        uri.clone().queryParam("param", "value"),
                        uri.clone().queryParam("a", 1).queryParam("b", 3),
                        uri.clone()
                                .queryParam("a")
                                .queryParam("b", 3)
                                .queryParam("c", true)
                                .queryParam("d", "string")
                                .queryParam("e", 3, true, 5, false, "value")
                ))
                .map(UriBuilder::build)
                .toList();
    }

    private static List<String> generateInvalidRedirectURIs() {
        List<String> uris = new ArrayList<>(List.of(
                "invalid",
                "",
                " ",
                "\t",
                " \t ",
                "http:/example.com",
                "http//example.com",
                "://example.com",
                "http://",
                "http://?",
                "http://#",
                "http://example .com",
                "http://example.com/pa th",
                "http://example.com/pa<th",
                "https://example.com/oauth/callback\n",
                "https://example.com/oauth/callback\r\n",
                "https://example.com/oauth/callback\t",
                "https://example.com/oauth/callback#fragment", // Fragments are not allowed in redirect URIs
                "https://user:password@localhost:8080/callback", // User info is not allowed in redirect URIs
                "http://localhost:8080/\u0000", // Null character
                "http://local host:8080/callback",
                "http://例子.测试/callback",
                "http://localhost:6060/oauth//callback",
                "https://thishostnameiswaytoolongtobevalidbecauseithasmorethanthesixtythreecharacterlimitsetbytherfc.org/callback",
                "https://this.url.is.too.long.because.it.has.more.than.two.hundered.fifty.three.characters." + "a".repeat(200) + ".com/callback"
        ));
        uris.add(null);
        return uris;
    }
}
