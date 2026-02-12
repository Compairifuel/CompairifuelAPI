package org.compairifuel.compairifuelapi.authorization.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.IncorrectClaimException;
import io.jsonwebtoken.MissingClaimException;
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

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.List;
import java.util.stream.Stream;
import java.util.Arrays;

import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.UUID;

@Log(topic = "AuthCodeValidatorServiceImpl")
@Default
public class AuthCodeValidatorServiceImpl implements IAuthCodeValidatorService {
    private IEnvConfig envConfig;
    private static final String TOKEN_TYPE = "Bearer";
    private static final long EXPIRES_IN = 3600000;

    @Override
    public long getExpiresIn() {
        return EXPIRES_IN;
    }

    @Inject
    public void setEnvConfig(IEnvConfig envConfig) {
        this.envConfig = envConfig;
    }

    @Override
    public String getTokenType() {
        return TOKEN_TYPE;
    }

    @Override
    public boolean isValid(String accessToken, List<String> scopes) {
        return retrieveJwtsClaims(accessToken,"CompairifuelAPI", scopes) != null;
    }

    @Override
    public Claims retrieveJwtsClaims(String jwtToken, String audience, List<String> scopes) {
        Claims claims;
        try {
            String encryptedSignedJwt = new String(Jwts.parser()
            .verifyWith(getSecretKey())
            .build()
            .parseSignedContent(jwtToken)
            .getPayload());

            String signedJwt = cryptMessage(Cipher.DECRYPT_MODE, encryptedSignedJwt);

            claims = Jwts
                    .parser()
                    .requireIssuer("Compairifuel")
                    .requireAudience(audience)
                    .verifyWith(getSecretKey())
                    .build()
                    .parseSignedClaims(signedJwt)
                    .getPayload();
            
            if (claims.getSubject() == null || claims.getId() == null || claims.getIssuedAt() == null || claims.getExpiration() == null || claims.getIssuer() == null || claims.getNotBefore() == null) {
                log.warning("The token is missing required claims!");
                throw new ForbiddenException();
            }

            String scopeClaim = claims.get("scope", String.class);
            if (!((scopeClaim.isBlank() || scopeClaim == null) && scopes.isEmpty()) && Stream.of(scopeClaim.split(" ")).noneMatch(s -> ((!s.isBlank()) && scopes.contains(s)))) {
                log.warning("The token doesn't have the required scope!");
                throw new ForbiddenException();
            }

        } catch (SignatureException ex) {
            log.warning("The token is not valid: " + ex.getMessage());
            throw new ForbiddenException();
        } catch (ExpiredJwtException ex) {
            log.warning("The token has expired: " + ex.getMessage());
            throw new ForbiddenException();
        } catch (MissingClaimException | IncorrectClaimException ex) {
            log.warning("The token is missing required claims: " + ex.getMessage());
            throw new ForbiddenException();
        } catch (JwtException ex) {
            log.severe("An error occured during the Jwts parser: " + ex.getMessage());
            throw new InternalServerErrorException();
        }

        return claims;
    }

    @Override
    public String createJwtsToken(HashMap<String, Object> claims, Date expiration, Date issuedAt, String subject, String scope) {
        String payload = Jwts.builder().claims(claims).signWith(getSecretKey()).expiration(expiration).issuedAt(issuedAt).issuer("Compairifuel").audience().add("CompairifuelAPI").and().subject(subject).notBefore(issuedAt).id(UUID.randomUUID().toString()).claim("scope", scope).compact();
        String encryptedPayload = cryptMessage(Cipher.ENCRYPT_MODE, payload);
        return Jwts.builder().content(encryptedPayload).signWith(getSecretKey()).header().add("typ", "JWT").add("cty", "JWT").and().compact();
    }

    private SecretKey getSecretKey() {
        String secretKey = envConfig.getEnv("SECRET_KEY");
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private SecretKey getEncryptionKey() {
        String secretKey = envConfig.getEnv("ENCRYPTION_KEY");
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return new SecretKeySpec(keyBytes, "AES");
    }

    private String cryptMessage(int optmode, String message) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKey key = getEncryptionKey();

            return switch (optmode) {
                case Cipher.ENCRYPT_MODE -> encrypt(cipher, key, message);
                case Cipher.DECRYPT_MODE -> decrypt(cipher, key, message);
                default -> throw new IllegalArgumentException("Unsupported mode: " + optmode);
            };

        } catch (Exception ex) {
            log.severe("Cryptography error (" + optmode + "): " + ex.getMessage());
            throw new InternalServerErrorException();
        }
    }

    private String encrypt(Cipher cipher, SecretKey key, String message) throws InvalidKeyException, UnsupportedOperationException,IllegalBlockSizeException,BadPaddingException,IllegalStateException {
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] iv = cipher.getIV();
        byte[] cipherText = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

        byte[] combined = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(cipherText, 0, combined, iv.length, cipherText.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    private String decrypt(Cipher cipher, SecretKey key, String message) throws InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedOperationException,IllegalBlockSizeException,BadPaddingException,IllegalStateException {
        byte[] decoded = Base64.getDecoder().decode(message);

        GCMParameterSpec spec =
            new GCMParameterSpec(128, decoded, 0, 12);

        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        byte[] plainText = cipher.doFinal(decoded, 12, decoded.length - 12);

        return new String(plainText, StandardCharsets.UTF_8);
    }
}
