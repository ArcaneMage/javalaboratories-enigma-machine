package org.javalaboratories.core.cryptography;

import org.javalaboratories.core.Try;
import org.javalaboratories.core.cryptography.keys.RsaKeys;
import org.javalaboratories.core.tuple.Pair;
import org.javalaboratories.core.tuple.Tuple2;
import org.javalaboratories.core.util.Arguments;
import org.javalaboratories.core.util.StopWatch;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

import static java.lang.StringTemplate.STR;
import static org.javalaboratories.core.cryptography.CommandLineArguments.ARG_INPUT_FILE;
import static org.javalaboratories.core.cryptography.CommandLineArguments.ARG_OUTPUT_FILE;
import static org.javalaboratories.core.cryptography.CommandLineArguments.ARG_PRIVATE_KEY_FILE;
import static org.javalaboratories.core.cryptography.CommandLineArguments.ARG_PUBLIC_KEY_FILE;
import static org.javalaboratories.core.cryptography.CommandLineArguments.Mode;

/**
 * Enigma Machine is an asymmetric cryptographic class that has the ability to
 * encrypt and decrypt files using the RSA algorithm.
 * <p>
 * There is no need to instantiate this class, because this is controlled and
 * managed by the main {@link Application} class, which among other things
 * also provides the {@link CommandLineArguments} object to this class'
 * constructor. It is important to note this class never accesses the arguments
 * directly, but only through the {@link CommandLineArguments} abstraction. It
 * encapsulates and validates the arguments, making them ready for use by this
 * class.
 * <p>
 * {@link EnigmaMachine#execute()} is the main method that determines the
 * current mode, whether encryption or decryption and delegates processing
 * accordingly.
 *
 * @see Application
 * @see CommandLineArguments
 */
public class EnigmaMachine {

    private static final Logger logger = LoggerFactory.getLogger(EnigmaMachine.class);

    private static final String DEFAULT_ENCRYPTED_FILE_EXTENSION = ".enc";
    private static final String DEFAULT_DECRYPTED_FILE_EXTENSION = ".dcr";

    private final CommandLineArguments arguments;
    private final Path fileInputPath;
    private final Path fileOutputPath;

    /**
     * Constructs an instance of this class with the {@link CommandLineArguments}
     * arguments object.
     *
     * @param arguments object that encapsulates and validates the command-line
     *                  arguments presented to the {@link Application} class.
     */
    public EnigmaMachine(final CommandLineArguments arguments) {
        Objects.requireNonNull(arguments);
        this.arguments = arguments;
        fileInputPath = Paths.get(arguments.getValue(ARG_INPUT_FILE));
        String fop = arguments.getValue(ARG_OUTPUT_FILE);
        fileOutputPath = fop == null ? getFileOutputPath() : Paths.get(fop); // default to <file>.enc | <file>.dcr
    }

    /**
     * This is the method that performs the encryption/decryption work, as
     * dictated by the {@link CommandLineArguments} arguments object.
     * <p>
     * It delegates the process to either {@code this#tryEncrypt} or {@code
     * this#tryDecrypt} methods depending on the command-line arguments. If an
     * exception occurs, it will be logged to the console and {@code false}
     * as opposed to {@code true} is returned.
     *
     * @return boolean value: {@code true} if operation performed
     * successfully otherwise {@code false}.
     */
    public boolean execute() {
        RsaHybridCryptography cryptography = CryptographyFactory.getAsymmetricHybridCryptography();
        StopWatch watch = StopWatch.watch("execute");
        boolean result = watch.time(() ->
                Try.of(() -> new FileInputStream(fileInputPath.toFile()))
                .flatMap(istream -> arguments.getModeValue() == Mode.ENCRYPT
                        ? tryEncrypt(cryptography,istream)
                        : tryDecrypt(cryptography,istream))
                .onFailure(f -> logger.error("Failed to process file \"{}\", error: {}",fileInputPath,f.getMessage()))
                .fold(false, Function.identity()));
        if (result)
            logger.info("Processed \"{}\" file in {}ms", fileInputPath, watch.getTime(TimeUnit.MILLISECONDS));
        return result;
    }

    /**
     * Decrypts the {@code InputStream} using the {@code private key} and outputs
     * the decrypted data to a file.
     * <p>
     * If the output filename is unknown, the default name will be the {@code input
     * file's} filename with the extension ".dcr".
     *
     * @param cryptography object required for encryption/decryption operation.
     * @param istream InputStream object, normally file based.
     * @return try object encapsulating success/failure of decryption.
     */
    protected Try<Boolean> tryDecrypt(final RsaHybridCryptography cryptography, final InputStream istream) {
        Arguments.requireNonNull("Parameters cryptography and istream mandatory",cryptography,istream);
        return Try.of(() -> RsaKeys.getPrivateKeyFrom(new FileInputStream(arguments.getValue(ARG_PRIVATE_KEY_FILE))))
                .flatMap(privateKey -> tryDecrypt(cryptography,privateKey,istream));
    }

    /**
     * Encrypts the {@code InputStream} using the {@code public certificate} and
     * outputs the encrypted data to an output file.
     * <p>
     * If the output filename is unknown, the default name will be the {@code
     * input file's} filename with the extension ".enc".
     *
     * @param cryptography object required for encryption operation.
     * @param istream InputStream object, normally file based.
     * @return try object encapsulating success/failure of encryption.
     */
    protected Try<Boolean> tryEncrypt(final RsaHybridCryptography cryptography, final InputStream istream) {
        Arguments.requireNonNull("Parameters cryptography and istream mandatory",cryptography,istream);
        return Try.of(() -> RsaKeys.getPublicKeyFrom(new FileInputStream(arguments.getValue(ARG_PUBLIC_KEY_FILE))))
                .flatMap(publicKey -> tryEncrypt(cryptography,publicKey,istream));
    }

    private Path getFileOutputPath() {
        String ext = arguments.getModeValue() == Mode.ENCRYPT ? DEFAULT_ENCRYPTED_FILE_EXTENSION : DEFAULT_DECRYPTED_FILE_EXTENSION;
        return Paths.get(".", PathUtils.truncateFileExt(fileInputPath) + ext);
    }

    private Try<Boolean> tryDecrypt(final RsaHybridCryptography cryptography, final PrivateKey privateKey,
                                                   final InputStream istream) {
        return Try.of(() -> cryptography.decrypt(privateKey,istream,new FileOutputStream(fileOutputPath.toFile())))
                .onFailure(f -> logger.info(STR."Failed to decrypt message:\{f.getMessage()}"))
                .map(Objects::nonNull);
    }

    private Try<Boolean> tryEncrypt(final RsaHybridCryptography cryptography, final PublicKey publicKey,
                                                   final InputStream istream) {
        return Try.of(() -> cryptography.encrypt(publicKey,istream,new FileOutputStream(fileOutputPath.toFile())))
                .onFailure(f -> logger.info(STR."Failed to encrypt message:\{f.getMessage()}"))
                .map(Objects::nonNull);
    }
}
