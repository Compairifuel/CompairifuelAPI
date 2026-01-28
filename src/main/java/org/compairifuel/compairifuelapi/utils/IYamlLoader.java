package org.compairifuel.compairifuelapi.utils;

import java.util.stream.Stream;
import java.io.IOException;

public interface IYamlLoader {
    public <T> Stream<T> load(BufferedReader reader, Class<T> cls) throws IOException;
}
