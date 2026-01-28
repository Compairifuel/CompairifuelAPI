package org.compairifuel.compairifuelapi.authorization.dataAccess;

public final class AuthClient {
    @JsonProperty("clientId")
    public String clientId;

    @JsonProperty("clientSecret")
    public String clientSecret;

    @JsonProperty("redirectUris")
    public List<String> redirectUris;

    @JsonProperty("enabled")
    public boolean enabled = true;
}
