package org.compairifuel.compairifuelapi.authorization.presentation;

import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.InternalServerErrorException;
import org.compairifuel.compairifuelapi.authorization.service.IAuthCodeValidatorService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrowsExactly;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;

import java.util.List;

class AuthCodeValidatorControllerTest {
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
        when(authCodeValidatorService.isValid(token, List.of())).thenReturn(true);

        // Act
        boolean result = sut.authenticateToken(token, List.of());

        // Assert
        assertTrue(result);
        verify(authCodeValidatorService).isValid(token, List.of());
    }

    @Test
    void authenticateTokenThrowsForbiddenException() {
        // Arrange
        String token = "invalid.token";
        when(authCodeValidatorService.isValid(token, List.of())).thenThrow(new ForbiddenException());

        // Assert
        assertThrowsExactly(ForbiddenException.class, () -> sut.authenticateToken(token, List.of()));
        verify(authCodeValidatorService).isValid(token, List.of());
    }

    @Test
    void authenticateTokenThrowsInternalServerErrorException() {
        // Arrange
        String token = "server.error.token";
        when(authCodeValidatorService.isValid(token, List.of())).thenThrow(new InternalServerErrorException());

        // Assert
        assertThrowsExactly(InternalServerErrorException.class, () -> sut.authenticateToken(token, List.of()));
        verify(authCodeValidatorService).isValid(token, List.of());
    }
}
