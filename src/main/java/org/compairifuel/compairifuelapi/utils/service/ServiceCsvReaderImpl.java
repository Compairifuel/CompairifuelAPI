package org.compairifuel.compairifuelapi.utils.service;

import jakarta.enterprise.inject.Default;
import lombok.extern.java.Log;

import java.io.*;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

@Log(topic = "ServiceCsvReaderImpl")
@Default
public class ServiceCsvReaderImpl implements IServiceCsvReader {
    /**
    * Gets a stream from a CSV resource.
    * 
    * @param resourceName The name of the resource.
    * @param delimiter The delimiter used in the CSV.
    * @param lineOffset The line offset to start reading from.
    * 
    * @return Stream<List<String>>: The output as a Stream. Close this Stream.
    * @throws IOException: When the reader is failing.
     **/
    @Override
    public Stream<List<String>> getStreamFromResource(String resourceName, String delimiter, long lineOffset) throws IOException, UncheckedIOException {
        BufferedReader br = startBufferedReaderFromResource(resourceName);

        return br.lines()
            .skip(lineOffset)
            .map(line -> Arrays.asList(line.split(delimiter)))
            .onClose(() -> {
                try {
                    br.close();
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            });
    }

    private BufferedReader startBufferedReaderFromResource(String resourceName) throws IOException, UncheckedIOException{
        try {
            InputStream is = getClass()
                .getClassLoader()
                .getResources(resourceName).nextElement().openStream();

            return new BufferedReader(new InputStreamReader(is));
        } catch (Exception e) {
            throw new UncheckedIOException(
                new FileNotFoundException("Resource not found: " + resourceName)
            );
        }
    }
}
