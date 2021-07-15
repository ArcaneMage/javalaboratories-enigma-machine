package org.javalaboratories.core.cryptography;

import org.javalaboratories.core.Try;

import java.io.PrintWriter;

/**
 * Concrete implementations abstract the arguments used by the {@link
 * EnigmaMachine}.
 * <p>
 * Arguments are validated against internal rules applied by the {@code parser}.
 * The purpose of this object is to ensure all necessary arguments are present
 * and correct.
 *
 * @see DefaultCommandLineArguments
 */
public interface CommandLineArguments {
    enum Mode {DECRYPT, ENCRYPT}

    String ARG_PRIVATE_KEYS_ALIAS = "a";
    String ARG_CERTIFICATE = "c";
    String ARG_DECRYPT = "d";
    String ARG_ENCRYPT = "e";
    String ARG_INPUT_FILE = "f";
    String ARG_HELP = "h";
    String ARG_OUTPUT_FILE = "o";
    String ARG_PRIVATE_KEYS_PASSWORD = "p";
    String ARG_KEYS_VAULT = "v";

    String LONG_ARG_PRIVATE_KEYS_ALIAS = "private-key-alias";
    String LONG_ARG_CERTIFICATE = "certificate";
    String LONG_ARG_DECRYPT = "decrypt";
    String LONG_ARG_ENCRYPT = "encrypt";
    String LONG_ARG_INPUT_FILE = "file";
    String LONG_ARG_OUTPUT_FILE = "output-file";
    String LONG_ARG_PRIVATE_KEYS_PASSWORD = "private-key-password";
    String LONG_ARG_KEYS_VAULT = "vault";

    /**
     * Parses the supplied arguments and validates them against argument rules.
     *
     * @param args an array of arguments originated from the command-line.
     * @throws IllegalArgumentException if any of arguments breaches the
     * validation rules.
     */
    Try<Boolean> parse(final String[] args);

    /**
     * Returns the value associated with a given parameter.
     * <p>
     * Note that some arguments do not have values, although this is legitimate,
     * {@code null} would be returned for such arguments. Consider using
     * {@link CommandLineArguments#getBoolValue(String)} instead.
     *
     * @param option the argument.
     * @return value associated with the argument.
     */
    String getValue(final String option);

    /**
     * Use this method to determine existence of arguments that do not have
     * {@code values} associated with them, but are considered as flags instead.
     *
     * @param option the argument.
     * @return {@code true} if the argument {@code flag} is present, otherwise
     * {@code false} is returned. Note that {@code false} would be returned
     * for arguments that are NOT considered as {@code flags}.
     */
    boolean getBoolValue(final String option);

    /**
     * Signifies whether {@code encryption} or {@code decryption} requested.
     *
     * @return {@link Mode#ENCRYPT} or {@link Mode#DECRYPT}.
     */
    Mode getModeValue();

    /**
     * Outputs arguments help information on the command-line.
     * <p>
     * Some implementations may not require a {@link PrintWriter}. Implementation
     * should make this clear in the documentation.
     *
     * @param writer object to which help output is written.
     */
    void printHelp(PrintWriter writer);
}
