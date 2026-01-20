package org.compairifuel.compairifuelapi.authorization.exceptions.mappers;

import jakarta.validation.ConstraintViolationException;
import jakarta.ws.rs.core.Response;
import org.compairifuel.compairifuelapi.exceptions.mappers.ConstraintViolationExceptionMapper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Set;

class ConstraintViolationExceptionMapperTest {

    @Test
    void TestQueryFailedException() {
        ConstraintViolationException constraintViolationException = new ConstraintViolationException("", Set.of());
        ConstraintViolationExceptionMapper constraintViolationExceptionMapper = new ConstraintViolationExceptionMapper();
        try (Response testValue = constraintViolationExceptionMapper.toResponse(constraintViolationException)) {
            Assertions.assertEquals(400, testValue.getStatus());
        }
    }
}
