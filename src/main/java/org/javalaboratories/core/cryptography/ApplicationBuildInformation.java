package org.javalaboratories.core.cryptography;

import lombok.Value;
import org.javalaboratories.core.Try;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

@Value
public class ApplicationBuildInformation {
    private static final String APPLICATION_PROPERTIES = "/application.properties";

    String artifact;
    String version;
    String timestamp;

    public ApplicationBuildInformation() {
        Properties properties = Try.with(() -> this.getClass().getResourceAsStream(APPLICATION_PROPERTIES), this::loadBuildProperties)
                .orElseThrow(() -> new IllegalStateException("Application properties not available"));
        artifact = properties.getProperty("artifact");
        version = properties.getProperty("version");
        timestamp = properties.getProperty("build.timestamp");
    }

    private Properties loadBuildProperties(InputStream stream) throws IOException {
        Properties p = new Properties();
        p.load(stream);
        return p;
    }
}
