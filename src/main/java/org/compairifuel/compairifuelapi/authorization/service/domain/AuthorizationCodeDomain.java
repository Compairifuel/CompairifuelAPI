package org.compairifuel.compairifuelapi.authorization.service.domain;

import lombok.Data;
import lombok.Generated;

import java.net.URI;

@Data
@Generated
public class AuthorizationCodeDomain {
    private String authorizationCode;
    private URI redirectToUri;
}
