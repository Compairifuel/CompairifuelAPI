package org.compairifuel.compairifuelapi.utils.service;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.List;
import java.util.stream.Stream;

public interface IServiceCsvReader {
    public Stream<List<String>> getStreamFromResource(String resource, String delimiter, long lineOffset) throws IOException, UncheckedIOException;
}
