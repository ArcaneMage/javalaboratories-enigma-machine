package org.javalaboratories.core.cryptography;

import org.javalaboratories.core.Eval;
import org.javalaboratories.core.Try;
import org.javalaboratories.core.cryptography.model.yaml.DefaultConfig;
import org.javalaboratories.core.cryptography.model.yaml.Defaults;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;
import org.yaml.snakeyaml.introspector.Property;
import org.yaml.snakeyaml.introspector.PropertyUtils;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public final class Configuration {

    private static final String CONFIGURATION_FILE="default-config.yml";
    private static final String HOME = "EM_HOME";

    // If in test mode, assume config directory in current directory.
    private static final boolean _TEST_MODE = "true".equals(System.getProperty("TEST_MODE"));

    private final Eval<Defaults> defaults;

    public Configuration() {
        defaults = Eval.later(this::initialise);
    }

    public String getHome() {
        return System.getenv(HOME) == null ? "" : System.getenv(HOME);
    }

    public String getConfigDirectory() {
        String enigmaHome = _TEST_MODE ? "" : getHome();
        return "".equals(enigmaHome) ? "" : enigmaHome + File.separator+"config";
    }

    public Defaults getDefaults() {
        return defaults.get();
    }

    private Defaults initialise() {
        return Try.of(() -> Files.readAllLines(Paths.get(getConfigDirectory(),CONFIGURATION_FILE)))
                .map(this::listToString)
                .map(s -> (DefaultConfig) newYaml().load(s))
                .map(DefaultConfig::getDefaults)
                .orElseThrow(() -> new IllegalStateException("Configuration content is not valid or configuration file not found"));
    }

    private String listToString(final List<String> list) {
        StringBuilder b = new StringBuilder();
        list.forEach(s -> b.append(s).append("\n")); //Preserve new lines for Yaml format
        return new String(b);
    }

    private Yaml newYaml() {
        Constructor c = new Constructor(DefaultConfig.class);
        c.setPropertyUtils(new PropertyUtils() {
            @Override
            public Property getProperty(Class<? extends Object> type, String name) {
                if ( name.indexOf('-') > -1 ) {
                    name = toCamelCase(name);
                }
                return super.getProperty(type, name);
            }
        });
        return new Yaml(c);
    }

    private String toCamelCase(String name) {
        name = name.toLowerCase();
        String[] str = name.split("-");
        String results = Arrays.stream(str)
                .skip(1)
                .map(s -> s.substring(0,1).toUpperCase()+(s.length() > 1 ? s.substring(1) : ""))
                .collect(Collectors.joining());
        return str.length > 0 ? str[0]+results : "";
    }
}
