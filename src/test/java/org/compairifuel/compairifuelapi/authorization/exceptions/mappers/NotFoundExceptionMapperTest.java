package org.compairifuel.compairifuelapi.authorization.exceptions.mappers;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.NotFoundException;
import org.compairifuel.compairifuelapi.exceptions.mappers.NotFoundExceptionMapper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;


class NotFoundExceptionMapperTest {
    @Test
    void TestQueryFailedException() {
        NotFoundException notFoundException = new NotFoundException();
        NotFoundExceptionMapper notFoundExceptionMapper = new NotFoundExceptionMapper();
        try (Response testValue = notFoundExceptionMapper.toResponse(notFoundException)) {
            Assertions.assertEquals(404, testValue.getStatus());
        }
    }
}
