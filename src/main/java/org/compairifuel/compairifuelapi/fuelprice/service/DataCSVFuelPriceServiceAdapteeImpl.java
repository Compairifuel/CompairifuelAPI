package org.compairifuel.compairifuelapi.fuelprice.service;

import jakarta.enterprise.inject.Default;
import jakarta.inject.Inject;
import jakarta.ws.rs.NotFoundException;
import lombok.extern.java.Log;
import org.compairifuel.compairifuelapi.fuelprice.mapper.IFuelPriceMapper;
import org.compairifuel.compairifuelapi.fuelprice.presentation.FuelPriceResponseDTO;
import org.compairifuel.compairifuelapi.utils.service.IServiceCsvReader;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Stream;

@Log(topic = "DataCSVFuelPriceServiceAdapteeImpl")
@Default
public class DataCSVFuelPriceServiceAdapteeImpl implements IFuelPriceServiceAggregatorAdapter {
    private static final String RESOURCE_NAME = "data.csv";
    private static final String DELIMITER = ";";
    private IFuelPriceMapper fuelPriceMapper;
    private IServiceCsvReader serviceCsvReader;

    @Inject
    public void setFuelPriceMapper(IFuelPriceMapper fuelPriceMapper){
        this.fuelPriceMapper = fuelPriceMapper;
    }

    @Inject
    public void setServiceCsvReader(IServiceCsvReader serviceCsvReader){
        this.serviceCsvReader = serviceCsvReader;
    }

    @Override
    public List<FuelPriceResponseDTO> getPrices(String fuelType, String address) throws NotFoundException {
        List<FuelPriceResponseDTO> list = this.filterPricesFromCsv(column -> column.get(4).equals(fuelType) && column.get(0).equals(address));

        if (list.isEmpty()) {
            log.info("No fuel prices found for address: " + address);
            throw new NotFoundException("No fuel prices found for address: " + address);
        }

        return list;
    }

    @Override
    public List<FuelPriceResponseDTO> getPrices(String fuelType, double latitude, double longitude) throws NotFoundException {
        // this is to add a 5m leeway to the latitude and longitude.
        double circa = 0.00005;

        List<FuelPriceResponseDTO> list = this.filterPricesFromCsv(column -> (column.get(4).equals(fuelType) && (Double.parseDouble(column.get(2)) <= (latitude + circa) && Double.parseDouble(column.get(2)) >= (latitude - circa)) && (Double.parseDouble(column.get(3)) <= longitude + circa && Double.parseDouble(column.get(3)) >= longitude - circa)));

        if (list.isEmpty()) {
            log.info("No fuel prices found for latitude and longitude: " + latitude + ", " + longitude);
            throw new NotFoundException("No fuel prices found for latitude and longitude: " + latitude + ", " + longitude);
        }

        return list;
    }

    @Override
    public List<FuelPriceResponseDTO> getPrices(String fuelType, String address, double latitude, double longitude) throws NotFoundException {
        // this is to add a 5m leeway to the latitude and longitude.
        double circa = 0.00005;

        List<FuelPriceResponseDTO> list = this.filterPricesFromCsv(column -> (column.get(4).equals(fuelType) && (Double.parseDouble(column.get(2)) <= latitude + circa && Double.parseDouble(column.get(2)) >= latitude - circa) && (Double.parseDouble(column.get(3)) <= longitude + circa && Double.parseDouble(column.get(3)) >= longitude - circa) || column.get(0).equals(address)));

        if (list.isEmpty()) {
            log.info("No fuel prices found on adress: " + address + " with latitude and longitude: " + latitude + ", " + longitude);
            throw new NotFoundException("No fuel prices found for adress: " + address + " with latitude and longitude: " + latitude + ", " + longitude);
        }

        return list;
    }

    private List<FuelPriceResponseDTO> filterPricesFromCsv(Predicate<List<String>> predicate) throws NotFoundException {
        try (
            Stream<List<String>> row = serviceCsvReader.getStreamFromResource(RESOURCE_NAME, DELIMITER, 1)
        )
        {
            return row
                    .filter(predicate)
                    .map(fuelPriceMapper::mapFuelPriceCSVRowToFuelPriceResponseDTO).toList();

        } catch (UncheckedIOException | IOException e) {
            log.severe("Error reading " + RESOURCE_NAME + " file: " + e.getMessage());
            throw new NotFoundException("No fuel prices found for predicate.");
        }
    }
}
