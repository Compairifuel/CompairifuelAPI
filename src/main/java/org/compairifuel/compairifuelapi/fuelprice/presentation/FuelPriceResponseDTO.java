package org.compairifuel.compairifuelapi.fuelprice.presentation;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Generated;
import lombok.NoArgsConstructor;
import org.compairifuel.compairifuelapi.utils.presentation.PositionDTO;

@AllArgsConstructor
@NoArgsConstructor
@Data
@Generated
public class FuelPriceResponseDTO {
    private PositionDTO position;
    private String address;
    private double price;
}
