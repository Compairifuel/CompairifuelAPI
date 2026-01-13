package org.compairifuel.compairifuelapi.authorization.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.enterprise.inject.Default;
import jakarta.inject.Inject;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.InternalServerErrorException;
import lombok.extern.java.Log;
import org.compairifuel.compairifuelapi.utils.IEnvConfig;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;

@Log(topic = "AuthCodeValidatorServiceImpl")
@Default
public class AuthCodeValidatorServiceImpl implements IAuthCodeValidatorService {
    private IEnvConfig envConfig;
    private static final String TOKEN_TYPE = "Bearer";
    private static final long EXPIRES_IN = 3600000;

    public long getExpiresIn() {
        return EXPIRES_IN;
    }

    @Inject
    public void setEnvConfig(IEnvConfig envConfig) {
        this.envConfig = envConfig;
    }

    public String getTokenType() {
        return TOKEN_TYPE;
    }

    public boolean isValid(String accessToken) {
        return retrieveJwtsClaims(accessToken) != null;
    }

    public Claims retrieveJwtsClaims(String JwtToken) {
        Claims claims;
        try {
            claims = Jwts
                    .parser()
                    .verifyWith(getSecretKey())
                    .build()
                    .parseSignedClaims(JwtToken)
                    .getPayload();
        } catch (SignatureException ex) {
            log.warning("The token is not valid: " + ex.getMessage());
            throw new ForbiddenException();
        } catch (ExpiredJwtException ex) {
            log.warning("The token has expired: " + ex.getMessage());
            throw new ForbiddenException();
        } catch (JwtException ex) {
            log.severe("An error occured during the Jwts parser: " + ex.getMessage());
            throw new InternalServerErrorException();
        }

        return claims;
    }

    public String createJwtsToken(HashMap<String, Object> claims, Date expiration, Date issuedAt) {
        return Jwts.builder().claims(claims).signWith(getSecretKey()).expiration(expiration).issuedAt(issuedAt).compact();
    }

    private SecretKey getSecretKey() {
        String secretKey = envConfig.getEnv("SECRET_KEY");
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
