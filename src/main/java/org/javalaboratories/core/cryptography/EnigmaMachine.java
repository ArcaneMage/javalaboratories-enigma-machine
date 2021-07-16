package org.javalaboratories.core.cryptography;

import org.javalaboratories.core.Maybe;
import org.javalaboratories.core.Try;
import org.javalaboratories.core.cryptography.keys.PrivateKeyStore;
import org.javalaboratories.core.handlers.Handlers;
import org.javalaboratories.core.util.Arguments;
import org.javalaboratories.core.util.StopWatch;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import static org.javalaboratories.core.cryptography.CommandLineArguments.ARG_CERTIFICATE;
import static org.javalaboratories.core.cryptography.CommandLineArguments.ARG_INPUT_FILE;
import static org.javalaboratories.core.cryptography.CommandLineArguments.ARG_KEYS_VAULT;
import static org.javalaboratories.core.cryptography.CommandLineArguments.ARG_OUTPUT_FILE;
import static org.javalaboratories.core.cryptography.CommandLineArguments.ARG_PRIVATE_KEYS_ALIAS;
import static org.javalaboratories.core.cryptography.CommandLineArguments.ARG_PRIVATE_KEYS_PASSWORD;
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

    private static final String PUBLIC_CERTIFICATE_TYPE = "X.509";
    private static final String DEFAULT_ENCRYPTED_FILE_EXTENSION = "._encrypted";
    private static final String DEFAULT_DECRYPTED_FILE_EXTENSION = "._decrypted";
    private static final String DEFAULT_KEYSTORE_PASSWORD = "changeit";

    private final CommandLineArguments arguments;
    private final Path fileInputPath;
    private final Path fileOutputPath;
    private final Path keyStoreFilePath;
    private final String privateKeyAlias;

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
        String ofile = arguments.getValue(ARG_OUTPUT_FILE);
        fileOutputPath = ofile == null ? null : Paths.get(ofile);
        keyStoreFilePath = Paths.get(arguments.getValue(ARG_KEYS_VAULT)); // already defaulted
        this.privateKeyAlias = arguments.getValue(ARG_PRIVATE_KEYS_ALIAS); // already defaulted
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
        AsymmetricCryptography cryptography = CryptographyFactory.getSunAsymmetricCryptography();
        StopWatch watch = StopWatch.watch("execute");
        boolean result = watch.time(() ->
                Try.of(() -> new FileInputStream(fileInputPath.toFile()))
                .flatMap(istream -> arguments.getModeValue() == Mode.ENCRYPT
                        ? tryEncrypt(cryptography,istream)
                        : tryDecrypt(cryptography,istream))
                .onFailure(f -> logger.error("Failed to process file \"{}\", error: {}",fileInputPath,f.getMessage()))
                .fold(f -> false,f -> true));
        if (result)
            logger.info("Processed \"{}\" file in {}ms", fileInputPath, watch.getTime(TimeUnit.MILLISECONDS));
        return result;
    }

    /**
     * Encrypts the {@code InputStream} using the {@code public certificate} and
     * outputs the encrypted data to an output file.
     * <p>
     * If the output filename is unknown, the default name will be the {@code
     * input file's} filename with the extension "._encrypted".
     * <p>
     * @param cryptography object required for encryption operation.
     * @param istream InputStream object, normally file based.
     * @return try object encapsulating success/failure of encryption.
     */
    protected Try<AsymmetricCryptography> tryEncrypt(final AsymmetricCryptography cryptography, final InputStream istream) {
        Arguments.requireNonNull("Parameters cryptography and istream mandatory",cryptography,istream);

        return Try.of(() -> CertificateFactory.getInstance(PUBLIC_CERTIFICATE_TYPE))
                .flatMap(factory -> Try.of(() -> factory.generateCertificate(new FileInputStream(arguments.getValue(ARG_CERTIFICATE)))))
                .flatMap(certificate -> tryEncrypt(cryptography,certificate,istream));
    }

    /**
     * Decrypts the {@code InputStream} using the {@code private key} and outputs
     * the decrypted data to a file.
     * <p>
     * If the output filename is unknown, the default name will be the {@code input
     * file's} filename with the extension "._decrypted". Decryption does require a
     * private key and this is retrieved from the default {@code keys-vault.jks}
     * file (overridable with the -v switch). Unless otherwise specified it is
     * assumed the private key is stored in the default {@code javalaboratories-org}
     * alias. This too is overridable with the {@code -a switch}.
     * <p>
     * @param cryptography object required for encryption operation.
     * @param istream InputStream object, normally file based.
     * @return try object encapsulating success/failure of decryption.
     */
    protected Try<AsymmetricCryptography> tryDecrypt(final AsymmetricCryptography cryptography, final InputStream istream) {
        Arguments.requireNonNull("Parameters cryptography and istream mandatory",cryptography,istream);

        return Try.of(() -> PrivateKeyStore.builder()
                    .keyStoreStream(new FileInputStream(keyStoreFilePath.toFile()))
                    .storePassword(DEFAULT_KEYSTORE_PASSWORD)
                    .build())
                .flatMap(this::tryPrivateKey)
                .flatMap(key -> tryDecrypt(cryptography,key,istream));
    }

    private File defaultOutputFile() {
        String ext = arguments.getModeValue() == Mode.ENCRYPT ? DEFAULT_ENCRYPTED_FILE_EXTENSION : DEFAULT_DECRYPTED_FILE_EXTENSION;
        return Paths.get(".", fileInputPath.getFileName().toString() + ext).toFile();
    }

    private OutputStream getOutputFileStream() {
        return Maybe.ofNullable(fileOutputPath)
                .map(Path::toFile)
                .map(Handlers.function(FileOutputStream::new))
                .orElseGet(Handlers.supplier(() -> new FileOutputStream(defaultOutputFile())));
    }

    private Try<AsymmetricCryptography> tryDecrypt(AsymmetricCryptography cryptography, PrivateKey privateKey, InputStream istream) {
        return Try.of (() -> {
            OutputStream ostream = getOutputFileStream();
            cryptography.decrypt(privateKey,istream,ostream);
            return cryptography;
        });
    }

    private Try<AsymmetricCryptography> tryEncrypt(AsymmetricCryptography cryptography, Certificate cert,InputStream istream) {
        return Try.of(() -> {
            OutputStream ostream = getOutputFileStream();
            cryptography.encrypt(cert, istream, ostream);
            return cryptography;
        });
    }

    private Try<PrivateKey> tryPrivateKey(PrivateKeyStore store) {
        PrivateKey key;
        try {
            key = store.getKey(privateKeyAlias, arguments.getValue(ARG_PRIVATE_KEYS_PASSWORD))
                    .orElseThrow(() -> new IllegalArgumentException("Private key not found/undefined"));
            return Try.success(key);
        } catch (CryptographyException | IllegalArgumentException e) {
            return Try.failure(e);
        }
    }
}
