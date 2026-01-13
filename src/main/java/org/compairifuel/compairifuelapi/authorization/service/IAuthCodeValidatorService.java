package org.compairifuel.compairifuelapi.authorization.service;

import io.jsonwebtoken.Claims;

import java.util.Date;
import java.util.HashMap;

public interface IAuthCodeValidatorService {
    String getTokenType();
    long getExpiresIn();
    boolean isValid(String accessToken);
    Claims retrieveJwtsClaims(String jwtToken);
    String createJwtsToken(HashMap<String, Object> claims, Date expiration, Date issuedAt);
}
