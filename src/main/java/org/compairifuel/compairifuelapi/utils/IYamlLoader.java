package org.compairifuel.compairifuelapi.utils;

import java.util.stream.Stream;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.UncheckedIOException;

public interface IYamlLoader {
    public <T> Stream<T> load(BufferedReader reader, Class<T> cls) throws IOException, UncheckedIOException;
}
