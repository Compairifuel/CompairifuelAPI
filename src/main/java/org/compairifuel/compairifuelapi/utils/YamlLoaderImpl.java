package org.compairifuel.compairifuelapi.utils;

import com.fasterxml.jackson.databind.MappingIterator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import java.io.BufferedReader;
import java.io.IOException;

import java.util.Spliterator;
import java.util.Spliterators;

import java.util.stream.Stream;
import java.util.stream.StreamSupport;

public class YamlLoaderImpl implements IYamlLoader {
    private static final ObjectMapper MAPPER =
            new ObjectMapper(new YAMLFactory());

    @Override
    public <T> Stream<T> load(BufferedReader reader, Class<T> cls) throws IOException {

        MappingIterator<T> it =
                MAPPER.readerFor(T.class).readValues(reader);

        return toStream(it);
    }

    private static <T> Stream<T> toStream(MappingIterator<T> it) {
        Spliterator<T> spliterator =
                Spliterators.spliteratorUnknownSize(
                        it,
                        Spliterator.ORDERED | Spliterator.NONNULL
                );

        return StreamSupport.stream(spliterator, false)
                .onClose(it::close);
    }
}
