package org.compairifuel.compairifuelapi.gasstation.presentation;

import lombok.Data;
import lombok.Generated;
import org.compairifuel.compairifuelapi.utils.presentation.PositionDTO;

import java.util.List;


@Data
@Generated
public class GasStationResponseDTO {
    private PositionDTO position;
    private String name;
    private String id;
    private String address;
    private List<PositionDTO> entryPoints;
    private List<PositionDTO> viewport;
}