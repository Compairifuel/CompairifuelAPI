package org.compairifuel.compairifuelapi.gasstation.service.domain;

import lombok.Data;
import lombok.Generated;

@Data
@Generated
public class SummaryDomain {
    private String queryType;
    private int queryTime;
    private int numResults;
    private int offset;
    private int totalResults;
    private int fuzzyLevel;
    private GeoBiasDomain geoBias;
}
