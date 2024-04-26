package org.javalaboratories.core.cryptography;

import org.junit.jupiter.api.*;

import java.io.File;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertTrue;

@TestMethodOrder(value = MethodOrderer.Alphanumeric.class)
public class EnigmaMachineTest {

    private Configuration configuration;

    @BeforeEach
    public void setup() {
        configuration = new Configuration();
    }

    @AfterAll
    public static void tearDown() {
        File ftextenc = new File("src/test/resources/text.out.enc");
        if (ftextenc.exists())
            ftextenc.delete();

        File ftextkey = new File("src/test/resources/text.out.key");
        if (ftextkey.exists())
            ftextkey.delete();

        File ftextout = new File("src/test/resources/text.out");
         if (ftextout.exists())
            ftextout.delete();
    }

    @Test
    public void testExecute_A_Encryption_Pass() {
        // Given
        CommandLineArguments arguments = new DefaultCommandLineArguments(configuration);
        arguments.parse(toArgs("-k=src/test/resources/rsa-public-key.pem -f=src/test/resources/text.original.data -e -o=src/test/resources/text.out.enc"));
        EnigmaMachine machine = new EnigmaMachine(arguments);

        // When
        boolean result = machine.execute();

        // Then
        assertTrue(result);
    }

    @Test
    public void testExecute_B_Decryption_Pass() {
        // Given
        CommandLineArguments arguments = new DefaultCommandLineArguments(configuration);
        arguments.parse(toArgs("-p=src/test/resources/rsa-private-key-pkcs8.pem -f=src/test/resources/text.out.enc -d -o=src/test/resources/text.out"));
        EnigmaMachine machine = new EnigmaMachine(arguments);

        // When
        boolean result = machine.execute();

        // Then
        assertTrue(result);
    }

    private String[] toArgs(String commandSyntax) {
        Objects.requireNonNull(commandSyntax);
        return commandSyntax.split(" ");
    }
}
