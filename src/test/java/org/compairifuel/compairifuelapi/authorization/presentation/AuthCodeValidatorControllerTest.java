package org.compairifuel.compairifuelapi.authorization.presentation;

import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.InternalServerErrorException;
import org.compairifuel.compairifuelapi.authorization.service.IAuthCodeValidatorService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

public class AuthCodeValidatorControllerTest {
    private final AuthCodeValidatorController sut = new AuthCodeValidatorController();
    private IAuthCodeValidatorService authCodeValidatorService;

    @BeforeEach
    void SetUp() {
        authCodeValidatorService = mock(IAuthCodeValidatorService.class);
        sut.setAuthCodeValidatorService(authCodeValidatorService);
        when(authCodeValidatorService.getTokenType()).thenReturn("Bearer");
    }

    @Test
    void authenticateTokenReturnsTrue() {
        // Arrange
        String token = "valid.token";
        when(authCodeValidatorService.isValid(token)).thenReturn(true);

        // Act
        boolean result = sut.authenticateToken(token);

        // Assert
        assertTrue(result);
        verify(authCodeValidatorService).isValid(token);
    }

    @Test
    void authenticateTokenThrowsForbiddenException() {
        // Arrange
        String token = "invalid.token";
        when(authCodeValidatorService.isValid(token)).thenThrow(new ForbiddenException());

        // Assert
        assertThrowsExactly(ForbiddenException.class, () -> sut.authenticateToken(token));
        verify(authCodeValidatorService).isValid(token);
    }

    @Test
    void authenticateTokenThrowsInternalServerErrorException() {
        // Arrange
        String token = "server.error.token";
        when(authCodeValidatorService.isValid(token)).thenThrow(new InternalServerErrorException());

        // Assert
        assertThrowsExactly(InternalServerErrorException.class, () -> sut.authenticateToken(token));
        verify(authCodeValidatorService).isValid(token);
    }
}
