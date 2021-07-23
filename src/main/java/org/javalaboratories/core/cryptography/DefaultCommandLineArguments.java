package org.javalaboratories.core.cryptography;

import org.apache.commons.cli.*;
import org.javalaboratories.core.Eval;
import org.javalaboratories.core.Try;

import java.io.PrintWriter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * This implementation abstracts the arguments used by the {@link EnigmaMachine}.
 * <p>
 * Arguments are validated against internal rules applied by the {@code parser}.
 * The purpose of this object is to ensure all necessary arguments are present
 * and correct.
 * <p>
 * {@link DefaultCommandLineArguments#printHelp(PrintWriter)} does not require
 * {@code PrintWriter}.
 * @see CommandLineParser
 */
public class DefaultCommandLineArguments implements CommandLineArguments {

    private static final String COMMAND_SYNTAX = "enigma-machine [--encrypt --certificate=<arg>] | " +
            "[--decrypt --private-key-password=<arg>] [--output-file=<arg>] -file=<arg>";

    private Mode mode;
    private CommandLine commandLine;
    private final Options options;
    private final Eval<Map<String,String>> defaultValues;
    private boolean initialised;
    private final Configuration configuration;

    /**
     * Constructor
     */
    public DefaultCommandLineArguments(Configuration c) {
        Objects.requireNonNull(c);
        defaultValues = Eval.later(this::createDefaultValues);
        options = createOptions();
        initialised = false;
        this.configuration = c;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Try<Boolean> parse(final String[] args) {
        Objects.requireNonNull(args);
        try {
            CommandLineParser parser = new DefaultParser();
            commandLine = parser.parse(options, args);

            applyArgumentRules();
            mode = commandLine.hasOption(ARG_DECRYPT) ? Mode.DECRYPT : Mode.ENCRYPT;
            initialised = true;
            return Try.success(initialised);
        } catch (Exception e) {
            return Try.failure(e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean getBoolValue(final String option) {
        Objects.requireNonNull(option);
        if (!initialised)
            throw new IllegalStateException();
        Option result = Arrays.stream(commandLine.getOptions())
                .filter(o -> o.getOpt().equals(option))
                .findFirst()
                .orElse(null);
        return result != null && !result.hasArg();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getValue(final String option) {
        Objects.requireNonNull(option);
        if (!initialised)
            throw new IllegalStateException();
        String value = commandLine.getOptionValue(option);
        // Check whether it's defaulted
        if (value == null)
            value = defaultValues
                    .get()
                    .get(option);
        return value;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Mode getModeValue() {
        if (!initialised)
            throw new IllegalStateException();
        return mode;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void printHelp(PrintWriter writer) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp(96,COMMAND_SYNTAX,"",options,"",false);
    }

    private void applyArgumentRules() {
        if (commandLine.hasOption(ARG_ENCRYPT)) {
            // Required args: -cf
            if (!(commandLine.hasOption(ARG_CERTIFICATE) && commandLine.hasOption(ARG_INPUT_FILE)))
                throw new IllegalArgumentException("Requires public certificate and a file to encrypt: -c -f");
            // Not allowable in encryption mode
            if (hasAnyOption(ARG_PRIVATE_KEYS_ALIAS,ARG_PRIVATE_KEYS_PASSWORD,ARG_KEYS_VAULT)) {
                throw new IllegalArgumentException("Arguments (-a,-p,-v) not allowable in encryption mode");
            }
        } else {
            if (commandLine.hasOption(ARG_DECRYPT)) {
                // Required args: -pf
                if (!(commandLine.hasOption(ARG_PRIVATE_KEYS_PASSWORD) && commandLine.hasOption(ARG_INPUT_FILE)))
                    throw new IllegalArgumentException("Requires private key password and a file to decrypt: -p -f");
                // Not allowable in decryption mode
                if (hasAnyOption(ARG_CERTIFICATE)) {
                    throw new IllegalArgumentException("Arguments (-c) not allowable in decryption mode");
                }
            } else
                throw new IllegalArgumentException("Which? Encryption or decryption, one or the other is required: -d | -e");
        }
    }

    private Options createOptions() {
        // enigma -v vaultFile -a privateKeyAlias -p privateKeyPasswd -c public-certificate -e encrypt -d decrypt
        Options result = new Options();
        result.addOption(Option.builder(ARG_PRIVATE_KEYS_ALIAS)
                    .longOpt(LONG_ARG_PRIVATE_KEYS_ALIAS)
                    .hasArg()
                    .desc("Private keys alias, default name \"private-key-alias\"")
                    .optionalArg(false)
                    .build())
                .addOption(Option.builder(ARG_PRIVATE_KEYS_PASSWORD)
                    .longOpt(LONG_ARG_PRIVATE_KEYS_PASSWORD)
                    .hasArg()
                    .desc("Private keys password")
                    .optionalArg(false)
                    .build())
                .addOption(Option.builder(ARG_CERTIFICATE)
                    .longOpt(LONG_ARG_CERTIFICATE)
                    .hasArg()
                    .desc("Public certificate file")
                    .build())
                .addOption(Option.builder(ARG_DECRYPT)
                    .longOpt(LONG_ARG_DECRYPT)
                    .hasArg(false)
                    .desc("Decrypt file")
                    .build())
                .addOption(Option.builder(ARG_ENCRYPT)
                    .longOpt(LONG_ARG_ENCRYPT)
                    .hasArg(false)
                    .desc("Encrypt file")
                    .build())
                .addOption(Option.builder(ARG_INPUT_FILE)
                    .longOpt(LONG_ARG_INPUT_FILE)
                    .hasArg()
                    .desc("File to encrypt/decrypt")
                    .optionalArg(false)
                    .build())
                .addOption(Option.builder(ARG_HELP)
                    .hasArg(false)
                    .desc("Help")
                    .build())
                .addOption(Option.builder(ARG_KEYS_VAULT)
                    .longOpt(LONG_ARG_KEYS_VAULT)
                    .hasArg(true)
                    .desc("Private keys vault, default name \"keys-vault.jks\"")
                    .optionalArg(false)
                    .build())
                .addOption(Option.builder(ARG_OUTPUT_FILE)
                    .longOpt(LONG_ARG_OUTPUT_FILE)
                    .hasArg(true)
                    .desc("Output filepath, default name is \"<file>._encrypted\" | \"<file>._decrypted\", depending on mode")
                    .optionalArg(false)
                    .build());
        return result;
    }

    private Map<String,String> createDefaultValues() {
        String keyStoreDir = configuration.getConfigDirectory();
        Map<String,String> result = new HashMap<>();
        result.put("a", configuration.getDefaults().getKeyStore().getPrivateKeyAlias());
        result.put("v", keyStoreDir+configuration.getDefaults().getKeyStore().getFile());
        return result;
    }

    private boolean hasAnyOption(String... options) {
        Objects.requireNonNull(options);
        return Arrays.stream(options)
                .anyMatch(commandLine::hasOption);
    }
}
