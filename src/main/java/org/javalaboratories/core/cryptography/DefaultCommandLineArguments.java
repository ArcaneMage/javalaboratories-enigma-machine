package org.javalaboratories.core.cryptography;

import org.apache.commons.cli.*;
import org.javalaboratories.core.Try;

import java.io.PrintWriter;
import java.util.Arrays;
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

    private static final String COMMAND_SYNTAX = "enigma-machine [--encrypt --public-key-file=<arg>] | " +
            "[--decrypt --private-key-file=<arg>] [--output-file=<arg>] -input-file=<arg>";

    private Mode mode;
    private CommandLine commandLine;
    private final Options options;
    private boolean initialised;
    private final Configuration configuration;

    /**
     * Constructor
     */
    public DefaultCommandLineArguments(Configuration c) {
        Objects.requireNonNull(c);
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
        return  commandLine.getOptionValue(option);
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
            // Required args: -kf
            if (!(commandLine.hasOption(ARG_PUBLIC_KEY_FILE) && commandLine.hasOption(ARG_INPUT_FILE)))
                throw new IllegalArgumentException("Requires public key and a file to encrypt: -k -f");
            // Not allowable in encryption mode
            if (hasAnyOption(ARG_PRIVATE_KEY_FILE)) {
                throw new IllegalArgumentException("Arguments (-d, -p) are not allowable in encryption mode");
            }
        } else {
            if (commandLine.hasOption(ARG_DECRYPT)) {
                // Required args: -pf
                if (!(commandLine.hasOption(ARG_PRIVATE_KEY_FILE) && commandLine.hasOption(ARG_INPUT_FILE)))
                    throw new IllegalArgumentException("Requires private key password and a file to decrypt: -p -f");
                // Not allowable in decryption mode
                if (hasAnyOption(ARG_PUBLIC_KEY_FILE)) {
                    throw new IllegalArgumentException("Arguments (-d, -k) not allowable in decryption mode");
                }
            } else
                throw new IllegalArgumentException("Which? Encryption or decryption, one or the other is required: -d | -e");
        }
    }

    private Options createOptions() {
        // enigma -v vaultFile -a privateKeyAlias -p privateKeyPasswd -c public-certificate -e encrypt -d decrypt
        Options result = new Options();
        result.addOption(Option.builder(ARG_PRIVATE_KEY_FILE)
                    .longOpt(LONG_ARG_PRIVATE_KEY_FILE)
                    .hasArg()
                    .desc("Private key file")
                    .optionalArg(false)
                    .build())
                .addOption(Option.builder(ARG_PUBLIC_KEY_FILE)
                    .longOpt(LONG_ARG_PUBLIC_KEY_FILE)
                    .hasArg()
                    .desc("Public key file")
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
                .addOption(Option.builder(ARG_OUTPUT_FILE)
                    .longOpt(LONG_ARG_OUTPUT_FILE)
                    .hasArg(true)
                    .desc("Output filepath, default name is \"<file>.enc\" | \"<file>.dcr\", depending on mode")
                    .optionalArg(false)
                    .build());
        return result;
    }

    private boolean hasAnyOption(String... options) {
        Objects.requireNonNull(options);
        return Arrays.stream(options)
                .anyMatch(commandLine::hasOption);
    }
}
