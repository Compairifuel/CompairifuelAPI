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

import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Date;
import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AuthCodeValidatorServiceImplTest {
    private final AuthCodeValidatorServiceImpl sut = new AuthCodeValidatorServiceImpl();
    private SecretKey key;

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
    }

    @Test
    void isValidReturnsTrue() {
        // Arrange
        final long expiresIn = 3600000;
        String accessToken = Jwts
                .builder()
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiresIn))
                .signWith(key)
                .compact();

        // Assert
        assertDoesNotThrow(() -> {
            // Act
            boolean result = sut.isValid(accessToken);
            assertTrue(result);
        });
    }

    @Test
    void isValidThrowsForbiddenExceptionWhenInvalidToken() {
        // Arrange
        var badKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(Encoders.BASE64.encode(new byte[258])));
        final long expiresIn = 3600000;
        String accessToken = Jwts
                .builder()
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiresIn))
                .signWith(badKey)
                .compact();

        // Assert
        assertThrowsExactly(ForbiddenException.class, () -> sut.isValid(accessToken));
    }

    @Test
    void isValidThrowsForbiddenExceptionWhenExpiredToken() {
        // Arrange
        final long expiresIn = -1;
        String accessToken = Jwts
                .builder()
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiresIn))
                .signWith(key)
                .compact();

        // Assert
        assertThrowsExactly(ForbiddenException.class, () -> sut.isValid(accessToken));
    }

    @Test
    void isValidThrowsInternalServerErrorException() {
        // Arrange
        String accessToken = Jwts.builder().signWith(key).compact();

        // Assert
        assertThrowsExactly(InternalServerErrorException.class, () -> sut.isValid(accessToken));
    }

    @Test
    void retrieveJwtsClaimsReturnsCorrectClaims() {
        // Arrange
        HashMap<String, Object> claims = new HashMap<>();
        claims.put("userId", 123);
        claims.put("role", "admin");

        Date issuedAt = new Date(System.currentTimeMillis());
        Date expiration = new Date(System.currentTimeMillis() + 3600000);

        String token = sut.createJwtsToken(claims, expiration, issuedAt);

        // Act
        Claims parsedClaims = sut.retrieveJwtsClaims(token);

        // Assert
        assertNotNull(parsedClaims);
        assertEquals(123, parsedClaims.get("userId"));
        assertEquals("admin", parsedClaims.get("role"));
        assertEquals(issuedAt.getTime() / 1000, parsedClaims.getIssuedAt().getTime() / 1000);
        assertEquals(expiration.getTime() / 1000, parsedClaims.getExpiration().getTime() / 1000);
    }

    @Test
    void retrieveJwtsClaimsThrowsForbiddenExceptionWhenSignatureInvalid() {
        // Arrange
        HashMap<String, Object> claims = new HashMap<>();
        claims.put("user", "bob");

        var badKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(Encoders.BASE64.encode(new byte[258])));
        Date expiration = new Date(System.currentTimeMillis() + 3600000);
        Date issuedAt = new Date(System.currentTimeMillis());

        String token = Jwts.builder()
                .claims(claims)
                .signWith(badKey)
                .expiration(expiration)
                .issuedAt(issuedAt)
                .compact();

        // Assert
        assertThrowsExactly(ForbiddenException.class, () -> sut.retrieveJwtsClaims(token));
    }

    @Test
    void retrieveJwtsClaimsThrowsForbiddenExceptionWhenExpired() {
        // Arrange
        HashMap<String, Object> claims = new HashMap<>();
        claims.put("expired", true);

        Date expiration = new Date(System.currentTimeMillis() - 1000);
        Date issuedAt = new Date(System.currentTimeMillis() - 2000);

        String token = sut.createJwtsToken(claims, expiration, issuedAt);

        // Assert
        assertThrowsExactly(ForbiddenException.class, () -> sut.retrieveJwtsClaims(token));
    }

    @Test
    void createJwtsTokenProducesValidSignedToken() {
        // Arrange
        HashMap<String, Object> claims = new HashMap<>();
        claims.put("username", "john_doe");

        Date issuedAt = new Date(System.currentTimeMillis());
        Date expiration = new Date(System.currentTimeMillis() + 60000);

        // Act
        String token = sut.createJwtsToken(claims, expiration, issuedAt);

        // Assert
        assertNotNull(token);
        assertDoesNotThrow(() -> {
            Claims parsed = sut.retrieveJwtsClaims(token);
            assertEquals("john_doe", parsed.get("username"));
        });
    }
}