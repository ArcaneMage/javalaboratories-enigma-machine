package org.javalaboratories.core.cryptography;

import org.javalaboratories.core.Maybe;
import org.javalaboratories.core.cryptography.keys.PrivateKeyStore;
import org.javalaboratories.core.handlers.Handlers;
import org.javalaboratories.core.util.Arguments;
import org.javalaboratories.core.util.StopWatch;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
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
     * It delegates the process to either {@code this#doEncrypt} or {@code
     * this#doDecrypt} methods depending on the command-line arguments. If an
     * exception occurs, it will be logged to the console and {@code false}
     * as opposed to {@code true} is returned.
     *
     * @return boolean value: {@code true} if operation performed
     * successfully otherwise {@code false}.
     */
    public boolean execute() {
        AsymmetricCryptography cryptography = CryptographyFactory.getSunAsymmetricCryptography();
        InputStream istream = getInputStream(fileInputPath)
                .orElseThrow(() -> new IllegalArgumentException(String.format("Input/output file error -- does the " +
                        "file \"%s\" exist? ",fileInputPath)));

        boolean result;
        StopWatch watch = StopWatch.watch("execute");
        if ( (result = watch.time(() -> arguments.getModeValue() == Mode.ENCRYPT
                ? doEncrypt(cryptography,istream)
                : doDecrypt(cryptography,istream))) ) {
            logger.info("Processed \"{}\" file in {}ms", fileInputPath, watch.getTime(TimeUnit.MILLISECONDS));
        }
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
     * @return true if encryption was successful.
     */
    protected boolean doEncrypt(final AsymmetricCryptography cryptography, final InputStream istream) {
        Arguments.requireNonNull("Parameters cryptography and istream mandatory",cryptography,istream);
        try {
            CertificateFactory factory = CertificateFactory.getInstance(PUBLIC_CERTIFICATE_TYPE);
            Certificate certificate = factory.generateCertificate(new FileInputStream(arguments.getValue(ARG_CERTIFICATE)));

            OutputStream ostream = getOutputFileStream();

            cryptography.encrypt(certificate, istream, ostream);
            return true;
        } catch (CertificateException e) {
            logger.error("Do not recognise certificate format: {}", e.getMessage());
        } catch (IOException e) {
            logger.error("Input/output file error -- does the files exist?: {}", e.getMessage());
        } catch (CryptographyException e) {
            logger.error("Failed to read encrypted file: {}", e.getMessage());
        }
        return false;
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
     * @return true if encryption was successful.
     */
    protected boolean doDecrypt(final AsymmetricCryptography cryptography, final InputStream istream) {
        Arguments.requireNonNull("Parameters cryptography and istream mandatory",cryptography,istream);
        try {
            PrivateKeyStore store = PrivateKeyStore.builder()
                    .keyStoreStream(new FileInputStream(keyStoreFilePath.toFile()))
                    .storePassword(DEFAULT_KEYSTORE_PASSWORD)
                    .build();

            PrivateKey key = store.getKey(privateKeyAlias,arguments.getValue(ARG_PRIVATE_KEYS_PASSWORD))
                    .orElseThrow(() -> new IllegalArgumentException("Private key not found/undefined"));
            OutputStream ostream = getOutputFileStream();

            cryptography.decrypt(key,istream,ostream);
            return true;
        } catch (FileNotFoundException e) {
            logger.error("Failed to read keys-vaults file: {}",e.getMessage());
        } catch (CryptographyException e) {
            logger.error("Failed to decrypt file: {}",e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("Wrong private key password? {}",e.getMessage());
        }
        return false;
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

    private Maybe<InputStream> getInputStream(final Path path) {
        Objects.requireNonNull(path);
        InputStream result;
        try {
            result = new FileInputStream(path.toFile());
        } catch (IOException e) {
            return Maybe.empty();
        }
        return Maybe.of(result);
    }
}
