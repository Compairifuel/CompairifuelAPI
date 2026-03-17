package org.compairifuel.compairifuelapi.fuelprice.presentation;

import jakarta.inject.Inject;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.compairifuel.compairifuelapi.authorization.presentation.AuthCodeValidatorController;
import org.compairifuel.compairifuelapi.fuelprice.service.IFuelPriceService;

import java.util.List;

@Path("")
public class FuelPriceController {
    private IFuelPriceService fuelPriceService;
    private AuthCodeValidatorController authCodeValidatorController;

    @Inject
    public void setFuelPriceService(IFuelPriceService fuelPriceService) {
        this.fuelPriceService = fuelPriceService;
    }

    @Inject
    public void setAuthCodeValidatorController(AuthCodeValidatorController authCodeValidatorController){
        this.authCodeValidatorController = authCodeValidatorController;
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/prices")
    public Response getPrices(@QueryParam("fuelType") @NotBlank(message="Fuel type is required.") String fuelType, @QueryParam("address") String address, @QueryParam("lat") @Min(value=-180,message="latitude cannot be less than -180.") @Max(value=180,message="latitude cannot be greater that 180.") Double latitude, @QueryParam("lng") @Min(value=-180,message="longitude cannot be less than -180.") @Max(value=180,message="longitude cannot be greater that 180.") Double longitude, @HeaderParam("Authorization") String authorization) {
        authCodeValidatorController.authenticateToken(authorization, List.of());

        List<FuelPriceResponseDTO> prices;
        if(fuelType != null && address != null && latitude != null && longitude != null) {
            prices = fuelPriceService.getPrices(fuelType, address, latitude, longitude);
        } else if(fuelType != null && address != null) {
            prices = fuelPriceService.getPrices(fuelType, address);
        } else if(fuelType != null && latitude != null && longitude != null) {
            prices = fuelPriceService.getPrices(fuelType, latitude, longitude);
        } else {
            throw new BadRequestException("Invalid query parameters. Please provide either fuelType and address or fuelType, latitude and longitude.");
        }

        return Response.ok().entity(prices).build();
    }
}
