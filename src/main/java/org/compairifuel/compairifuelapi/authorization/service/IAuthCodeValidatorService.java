package org.compairifuel.compairifuelapi.authorization.service;

import io.jsonwebtoken.Claims;

import java.util.Date;
import java.util.HashMap;
import java.util.List;

public interface IAuthCodeValidatorService {
    String getTokenType();
    long getExpiresIn();
    boolean isValid(String accessToken, List<String> scopes);
    Claims retrieveJwtsClaims(String jwtToken, String audience, List<String> scopes);
    String createJwtsToken(HashMap<String, Object> claims, Date expiration, Date issuedAt, String subject, String scope);
}
