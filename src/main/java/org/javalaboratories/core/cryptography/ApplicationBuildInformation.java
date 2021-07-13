package org.javalaboratories.core.cryptography;

import lombok.Value;

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
        InputStream istream = this.getClass().getResourceAsStream(APPLICATION_PROPERTIES);
        Properties properties = new Properties();
        try {
            properties.load(istream);
        } catch (IOException e) {
            // Handled
        }
        artifact = properties.getProperty("artifact");
        version = properties.getProperty("version");
        timestamp = properties.getProperty("build.timestamp");

    }
}
