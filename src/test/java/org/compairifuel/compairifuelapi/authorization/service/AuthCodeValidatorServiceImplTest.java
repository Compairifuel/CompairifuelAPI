package org.compairifuel.compairifuelapi.authorization.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.InternalServerErrorException;
import org.compairifuel.compairifuelapi.utils.IEnvConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthCodeValidatorServiceImplTest {
    private final AuthCodeValidatorServiceImpl sut = new AuthCodeValidatorServiceImpl();
    private SecretKey key;
    private SecretKey encryptionAESGCMKey;

    @BeforeEach
    void setUp() {
        IEnvConfig envConfig = mock(IEnvConfig.class);
        sut.setEnvConfig(envConfig);

        try {
            var random = SecureRandom.getInstanceStrong();
            random.setSeed(4321);
            var temp = Encoders.BASE64.encode(random.generateSeed(256));

            when(envConfig.getEnv("SECRET_KEY")).thenReturn(temp);
            key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(temp));
        } catch (NoSuchAlgorithmException e) {
            var temp = Encoders.BASE64.encode(new byte[256]);
            when(envConfig.getEnv("SECRET_KEY")).thenReturn(temp);
            key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(temp));
        }

        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            
            var random = SecureRandom.getInstanceStrong();
            random.setSeed(4321);
            keyGen.init(256, random);
            var temp = Encoders.BASE64.encode(keyGen.generateKey().getEncoded());
            when(envConfig.getEnv("ENCRYPTION_KEY")).thenReturn(temp);
            encryptionAESGCMKey = new SecretKeySpec(Decoders.BASE64.decode(temp), "AES");
        } catch (NoSuchAlgorithmException e) {
            var temp = Encoders.BASE64.encode(new byte[256]);
            when(envConfig.getEnv("ENCRYPTION_KEY")).thenReturn(temp);
            encryptionAESGCMKey = new SecretKeySpec(Decoders.BASE64.decode(temp), "AES");
        }

    }

    @Test
    void isValidReturnsTrue() throws Exception {
        // Arrange
        final long expiresIn = 3600000;
        String payload = Jwts
                .builder()
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiresIn))
                .subject("test-subject")
                .issuer("Compairifuel")
                .audience().add("CompairifuelAPI").and()
                .id("unique-token-id")
                .claims().add("scope", "admin:read user:write").and()
                .notBefore(new Date(System.currentTimeMillis()))
                .signWith(key)
                .compact();

        String encryptedPayload = encryptPayload(payload);
        String accessToken = Jwts.builder().content(encryptedPayload).signWith(key).header().add("typ", "JWT").add("cty", "JWT").and().compact();

        // Assert
        assertDoesNotThrow(() -> {
            // Act
            boolean result = sut.isValid(accessToken, List.of("admin:read", "user:write"));
            assertTrue(result);
        });
    }

    @Test
    void isValidWithMissingScopeClaimReturnsTrue() throws Exception {
        // Arrange
        final long expiresIn = 3600000;
        String payload = Jwts
                .builder()
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiresIn))
                .subject("test-subject")
                .issuer("Compairifuel")
                .audience().add("CompairifuelAPI").and()
                .id("unique-token-id")
                .claims().add("scope", "admin:read user:write").and()
                .notBefore(new Date(System.currentTimeMillis()))
                .signWith(key)
                .compact();

        String encryptedPayload = encryptPayload(payload);
        String accessToken = Jwts.builder().content(encryptedPayload).signWith(key).header().add("typ", "JWT").add("cty", "JWT").and().compact();

        // Assert
        assertThrowsExactly(ForbiddenException.class, () -> {
            // Act
            boolean result = sut.isValid(accessToken, List.of("admin:write"));
            assertFalse(result);
        });
    }

    @Test
    void isValidWithWrongClaimsThrowsForbiddenException() throws Exception {
        // Arrange
        final long expiresIn = 3600000;
        String payload = Jwts
                .builder()
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiresIn))
                .subject("test-subject")
                .issuer("UnknownIssuer")
                .audience().add("UnknownAudience").and()
                .id("unique-token-id")
                .claims().add("scope", null).and()
                .notBefore(new Date(System.currentTimeMillis()))
                .signWith(key)
                .compact();

        String encryptedPayload = encryptPayload(payload);
        String accessToken = Jwts.builder().content(encryptedPayload).signWith(key).header().add("typ", "JWT").add("cty", "JWT").and().compact();

        // Assert
        assertThrowsExactly(ForbiddenException.class, () -> sut.isValid(accessToken, List.of("admin:read", "user:write")));
    }

    @Test
    void isValidWithNoIssuedAtAndExpirationThrowsForbiddenException() throws Exception {
        // Arrange
        String payload = Jwts
                .builder()
                .issuer("Compairifuel")
                .audience().add("CompairifuelAPI").and()
                .claims().add("scope", "").and()
                .signWith(key)
                .compact();

        String encryptedPayload = encryptPayload(payload);
        String accessToken = Jwts.builder().content(encryptedPayload).signWith(key).header().add("typ", "JWT").add("cty", "JWT").and().compact();

        // Assert
        assertThrowsExactly(ForbiddenException.class, () -> sut.isValid(accessToken, List.of()));
    }

    @Test
    void isValidThrowsForbiddenExceptionWhenInvalidToken() throws Exception {
        // Arrange
        var badKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(Encoders.BASE64.encode(new byte[258])));
        final long expiresIn = 3600000;
        String payload = Jwts
                .builder()
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiresIn))
                .subject("test-subject")
                .audience().add("CompairifuelAPI").and()
                .claims().add("scope", "").and()
                .signWith(badKey)
                .compact();

        String encryptedPayload = encryptPayload(payload);
        String accessToken = Jwts.builder().content(encryptedPayload).signWith(badKey).header().add("typ", "JWT").add("cty", "JWT").and().compact();

        // Assert
        assertThrowsExactly(ForbiddenException.class, () -> sut.isValid(accessToken, List.of()));
    }

    @Test
    void isValidThrowsForbiddenExceptionWhenExpiredToken() throws Exception {
        // Arrange
        final long expiresIn = -1;
        String payload = Jwts
                .builder()
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiresIn))
                .subject("test-subject")
                .audience().add("CompairifuelAPI").and()
                .claims().add("scope", "").and()
                .signWith(key)
                .compact();

        String encryptedPayload = encryptPayload(payload);
        String accessToken = Jwts.builder().content(encryptedPayload).signWith(key).header().add("typ", "JWT").add("cty", "JWT").and().compact();

        // Assert
        assertThrowsExactly(ForbiddenException.class, () -> sut.isValid(accessToken, List.of()));
    }

    @Test
    void isValidThrowsInternalServerErrorException() throws Exception {
        // Arrange
        String payload = Jwts.builder().audience().add("CompairifuelAPI").and().claims().add("scope", "").and().issuer("Compairifuel").signWith(key).compact();
        String encryptedPayload = encryptPayload(payload);
        String accessToken = Jwts.builder().content(encryptedPayload).header().add("typ", "JWT").add("cty", "JWT").and().compact();

        // Assert
        assertThrowsExactly(InternalServerErrorException.class, () -> sut.isValid(accessToken, List.of()));
    }

    @Test
    void retrieveJwtsClaimsReturnsCorrectClaims() {
        // Arrange
        HashMap<String, Object> claims = new HashMap<>();
        claims.put("userId", 123);
        claims.put("role", "admin");
        claims.put("scope", "");
        Date issuedAt = new Date(System.currentTimeMillis());
        Date expiration = new Date(System.currentTimeMillis() + 3600000);

        String token = sut.createJwtsToken(claims, expiration, issuedAt, "test-subject", "");

        // Act
        Claims parsedClaims = sut.retrieveJwtsClaims(token, "CompairifuelAPI", List.of());

        // Assert
        assertNotNull(parsedClaims);
        assertEquals(123, parsedClaims.get("userId"));
        assertEquals("admin", parsedClaims.get("role"));
        assertEquals(issuedAt.getTime() / 1000, parsedClaims.getIssuedAt().getTime() / 1000);
        assertEquals(expiration.getTime() / 1000, parsedClaims.getExpiration().getTime() / 1000);
        assertEquals("test-subject", parsedClaims.getSubject());
    }

    @Test
    void retrieveJwtsClaimsThrowsForbiddenExceptionWhenSignatureInvalid() throws Exception {
        // Arrange
        HashMap<String, Object> claims = new HashMap<>();
        claims.put("user", "bob");
        claims.put("scope", "");

        var badKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(Encoders.BASE64.encode(new byte[258])));
        Date expiration = new Date(System.currentTimeMillis() + 3600000);
        Date issuedAt = new Date(System.currentTimeMillis());

        String payload = Jwts.builder()
                .claims(claims)
                .signWith(badKey)
                .expiration(expiration)
                .issuedAt(issuedAt)
                .subject("test-subject")
                .audience().add("CompairifuelAPI").and()
                .compact();

        String encryptedPayload = encryptPayload(payload);
        String token = Jwts.builder().content(encryptedPayload).signWith(badKey).header().add("typ", "JWT").add("cty", "JWT").and().compact();

        // Assert
        assertThrowsExactly(ForbiddenException.class, () -> sut.retrieveJwtsClaims(token, "CompairifuelAPI", List.of()));
    }

    @Test
    void retrieveJwtsClaimsThrowsForbiddenExceptionWhenExpired() {
        // Arrange
        HashMap<String, Object> claims = new HashMap<>();
        claims.put("expired", true);
        claims.put("scope", "");

        Date expiration = new Date(System.currentTimeMillis() - 1000);
        Date issuedAt = new Date(System.currentTimeMillis() - 2000);

        String token = sut.createJwtsToken(claims, expiration, issuedAt, "test-subject", "");

        // Assert
        assertThrowsExactly(ForbiddenException.class, () -> sut.retrieveJwtsClaims(token, "CompairifuelAPI", List.of()));
    }

    @Test
    void createJwtsTokenProducesValidSignedToken() {
        // Arrange
        HashMap<String, Object> claims = new HashMap<>();
        claims.put("username", "john_doe");
        claims.put("scope", "");
        Date issuedAt = new Date(System.currentTimeMillis());
        Date expiration = new Date(System.currentTimeMillis() + 60000);

        // Act
        String token = sut.createJwtsToken(claims, expiration, issuedAt, "test-subject", "");

        // Assert
        assertNotNull(token);
        assertDoesNotThrow(() -> {
            Claims parsed = sut.retrieveJwtsClaims(token, "CompairifuelAPI", List.of());
            assertEquals("john_doe", parsed.get("username"));
            assertEquals("test-subject", parsed.getSubject());
            assertEquals(claims.get("scope"), parsed.get("scope"));
        });
    }

    private String encryptPayload(String payload) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, encryptionAESGCMKey);

        byte[] iv = cipher.getIV();
        byte[] cipherText = cipher.doFinal(payload.getBytes(StandardCharsets.UTF_8));

        byte[] combined = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(cipherText, 0, combined, iv.length, cipherText.length);

        return Base64.getEncoder().encodeToString(combined);
    }
}