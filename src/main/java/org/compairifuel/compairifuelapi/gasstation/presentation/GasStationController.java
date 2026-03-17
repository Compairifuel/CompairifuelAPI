package org.compairifuel.compairifuelapi.gasstation.presentation;

import jakarta.inject.Inject;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.compairifuel.compairifuelapi.authorization.presentation.AuthCodeValidatorController;
import org.compairifuel.compairifuelapi.gasstation.service.IGasStationService;

import java.util.List;

@Path("")
public class GasStationController {
    private IGasStationService gasStationService;
    private AuthCodeValidatorController authCodeValidatorController;

    @Inject
    public void setGasStationService(IGasStationService gasStationService) {
        this.gasStationService = gasStationService;
    }

    @Inject
    public void setAuthCodeValidatorController(AuthCodeValidatorController authCodeValidatorController){
        this.authCodeValidatorController = authCodeValidatorController;
    }

    @GET
    @Path("/gasStations")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getGasStations(@QueryParam("lat") @Min(value=-180,message="latitude cannot be less than -180.") @Max(value=180,message="latitude cannot be greater that 180.") double latitude, @QueryParam("lng") @Min(value=-180,message="longitude cannot be less than -180.") @Max(value=180,message="longitude cannot be greater that 180.") double longitude, @HeaderParam("Authorization") String authorization) {
        authCodeValidatorController.authenticateToken(authorization, List.of());

        List<GasStationResponseDTO> gasStationEntities = gasStationService.getGasStations(latitude, longitude, 25000);
        return Response.ok().entity(gasStationEntities).build();
    }
}