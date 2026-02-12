package org.compairifuel.compairifuelapi.authorization.dataaccess;

import java.util.List;
import com.fasterxml.jackson.annotation.JsonProperty;

public final class AuthClient {
    @JsonProperty("clientId")
    public String clientId;

    @JsonProperty("clientSecret")
    public String clientSecret;

    @JsonProperty("redirectUris")
    public List<String> redirectUris;

    @JsonProperty("enabled")
    public boolean enabled = true;

    @JsonProperty("roles")
    public List<String> roles = List.of();
}
