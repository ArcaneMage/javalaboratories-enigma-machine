package org.javalaboratories.core.cryptography;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class EnigmaMachineTest {

    private Configuration configuration;

    @BeforeEach
    public void setup() {
        configuration = new Configuration();
    }

    @AfterEach
    public void tearDown() {
        File ftextenc = new File("src/test/resources/text.out.enc");
        if (ftextenc.exists())
            ftextenc.delete();

        File ftextout = new File("src/test/resources/text.out");
        if (ftextout.exists())
            ftextout.delete();
    }

    @Test
    public void testExecute_Encryption_Pass() {
        // Given
        CommandLineArguments arguments = new DefaultCommandLineArguments(configuration);
        arguments.parse(toArgs("-c=src/test/resources/public-certificate-test.cer -f=src/test/resources/text.original.data -e -o=src/test/resources/text.out.enc"));
        EnigmaMachine machine = new EnigmaMachine(arguments);

        // When
        boolean result = machine.execute();

        // Then
        assertTrue(result);
    }

    @Test
    public void testExecute_Decryption_Pass() {
        // Given
        CommandLineArguments arguments = new DefaultCommandLineArguments(configuration);
        arguments.parse(toArgs("-v=src/test/resources/keys-vault.jks -p=TESTING -f=src/test/resources/text.original.enc -d -o=src/test/resources/text.out"));
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
