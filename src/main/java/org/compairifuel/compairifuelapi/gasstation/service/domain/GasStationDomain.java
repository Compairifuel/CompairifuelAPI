package org.compairifuel.compairifuelapi.gasstation.service.domain;

import lombok.Data;
import lombok.Generated;

import java.util.List;

@Data
@Generated
public class GasStationDomain {
    private SummaryDomain summary;
    private List<ResultDomain> results;
}
