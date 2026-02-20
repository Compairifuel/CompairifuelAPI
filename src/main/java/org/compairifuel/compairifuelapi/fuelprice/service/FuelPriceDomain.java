package org.compairifuel.compairifuelapi.fuelprice.service;

import lombok.Data;
import lombok.Generated;

import java.util.List;

@Data
@Generated
public class FuelPriceDomain {
    private List<FuelDomain> fuels;
    private String fuelPrice;
}
