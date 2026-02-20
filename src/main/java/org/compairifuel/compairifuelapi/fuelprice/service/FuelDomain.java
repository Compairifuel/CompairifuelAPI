package org.compairifuel.compairifuelapi.fuelprice.service;

import lombok.Data;
import lombok.Generated;

import java.util.List;

@Data
@Generated
public class FuelDomain {
    private String type;
    private List<PriceDomain> price;
    private String updatedAt;
}
