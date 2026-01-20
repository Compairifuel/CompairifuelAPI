package org.compairifuel.compairifuelapi.authorization.exceptions.mappers;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import jakarta.ws.rs.core.Response;
import org.compairifuel.compairifuelapi.exceptions.mappers.ConstraintViolationExceptionMapper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ConstraintViolationExceptionMapperTest {

    private ConstraintViolationExceptionMapper sut;

    @BeforeEach
    void setUp() {
        sut = new ConstraintViolationExceptionMapper();
    }

    @Test
    void testConstraintViolationReturns400() {
        // Arrange
        ConstraintViolationException constraintViolationException = new ConstraintViolationException("", Set.of());
        // Act
        try (Response response = sut.toResponse(constraintViolationException)) {
            // Assert
            Assertions.assertEquals(400, response.getStatus());
        }
    }

    @Test
    void testSingleViolationContainsMessageWithNewline() {
        // Arrange
        ConstraintViolation<?> violation = mockViolation("must not be blank");
        ConstraintViolationException constraintViolationException = new ConstraintViolationException(Set.of(violation));

        // Act
        try (Response response = sut.toResponse(constraintViolationException)) {
            // Assert
            Assertions.assertEquals("must not be blank\n", response.getEntity());
        }
    }

    @Test
    void testMessageContainsMultipleViolations() {
        // Arrange
        ConstraintViolation<?> valueBlankViolation = mockViolation("must not be blank");
        ConstraintViolation<?> valueNegativeViolation = mockViolation("must be positive");
        Set<ConstraintViolation<?>> violations = new HashSet<>(Set.of(valueBlankViolation, valueNegativeViolation));
        ConstraintViolationException constraintViolationException = new ConstraintViolationException(violations);

        // Act
        try (Response response = sut.toResponse(constraintViolationException)) {
            String entity = (String) response.getEntity();
            // Assert
            Assertions.assertTrue(entity.contains("must not be blank\n"));
            Assertions.assertTrue(entity.contains("must be positive\n"));
        }
    }

    @Test
    void testEmptyViolationsReturnsEmptyString() {
        // Arrange
        ConstraintViolationException constraintViolationException = new ConstraintViolationException("", Set.of());

        // Act
        try (Response response = sut.toResponse(constraintViolationException)) {
            // Assert
            Assertions.assertEquals("", response.getEntity());
        }
    }

    @Test
    void testEveryViolationMessageEndsWithNewline() {
        // Arrange
        ConstraintViolation<?> valueBlankViolation = mockViolation("error one");
        ConstraintViolation<?> valueNegativeViolation = mockViolation("error two");
        Set<ConstraintViolation<?>> violations = new HashSet<>(Set.of(valueBlankViolation, valueNegativeViolation));
        ConstraintViolationException constraintViolationException = new ConstraintViolationException(violations);

        // Act
        try (Response response = sut.toResponse(constraintViolationException)) {
            String entity = (String) response.getEntity();
            long newlineCount = entity.chars().filter(c -> c == '\n').count();
            // Assert
            Assertions.assertEquals(2, newlineCount);
        }
    }

    @Test
    void testExceptionIsThrowable() {
        // Arrange
        ConstraintViolationException constraintViolationException = new ConstraintViolationException("error", null);
        // Assert
        Assertions.assertInstanceOf((Throwable.class), constraintViolationException);
    }

    private ConstraintViolation<?> mockViolation(String message) {
        ConstraintViolation<?> violation = mock(ConstraintViolation.class);
        when(violation.getMessage()).thenReturn(message);
        return violation;
    }
}
