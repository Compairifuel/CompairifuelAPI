package org.compairifuel.compairifuelapi.health.presentation;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@Path("")
public class HealthController {

    @GET
    @Path("/health")
    public Response getHealth() {
        return Response.ok("healthy").build();
    }
}
