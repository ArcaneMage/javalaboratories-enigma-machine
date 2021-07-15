package org.javalaboratories.core.cryptography;

import org.javalaboratories.core.cryptography.CommandLineArguments.Mode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Objects;

import static org.junit.jupiter.api.Assertions.*;

public class DefaultCommandLineArgumentsTest {

    private CommandLineArguments arguments;

    @BeforeEach
    public void setup() {
        arguments = new DefaultCommandLineArguments();
    }

    @Test
    public void testParse_MinimumDecryptArguments_Pass() {
        String[] args = toArgs("-p=6553772 -f=secret-text.txt._encrypted -d");
        arguments.parse(args);
        assertEquals("6553772",arguments.getValue("p"));
    }

    @Test
    public void testParse_AllowableDecryptArguments_Fail() {
        String[] args = toArgs("-p=6553772 -f=secret-text.txt._encrypted -d -c=javalaboratories-org.cer");

        boolean result = arguments.parse(args)
                .fold(f -> false, f -> true);
        assertFalse(result);
    }

    @Test
    public void testParse_MinimumEncryptArguments_Pass() {
        String[] args = toArgs("-c=javalaboratories-org.cer -f=secret-text.txt -e");
        arguments.parse(args);
        assertEquals("javalaboratories-org.cer",arguments.getValue("c"));
    }

    @Test
    public void testParse_AllowableEncryptArguments_Fail() {
        String[] args = toArgs("-c=javalaboratories-org.cer -f=secret-text.txt -e -a=private-key-alias -p=65537773 -v=private-vault.jks");
        boolean result = arguments.parse(args)
                .fold(f -> false, f -> true);
        assertFalse(result);
    }

    @Test
    public void testParse_InsufficientEncryptArguments_Fail() {
        String[] args = toArgs("-e");
        boolean result = arguments.parse(args)
                .fold(f -> false, f -> true);
        assertFalse(result);
    }

    @Test
    public void testParse_InsufficientDecryptArguments_Fail() {
        String[] args = toArgs("-d");
        boolean result = arguments.parse(args)
                .fold(f -> false, f -> true);
        assertFalse(result);
    }

    @Test
    public void testParse_ZeroArguments_Fail() {
        String[] args = toArgs("");
        boolean result = arguments.parse(args)
                .fold(f -> false, f -> true);
        assertFalse(result);
    }

    @Test
    public void testGetBoolValue_Pass() {
        String[] args = toArgs("-p=6553772 -f=secret-text.txt._encrypted -d");
        arguments.parse(args);

        assertTrue(arguments.getBoolValue("d"));
    }

    @Test
    public void testGetModeValue_Decrypt_Pass() {
        String[] args = toArgs("-p=6553772 -f=secret-text.txt._encrypted -d");
        arguments.parse(args);

        assertEquals(Mode.DECRYPT, arguments.getModeValue());
    }

    @Test
    public void testGetModeValue_Encrypt_Pass() {
        String[] args = toArgs("-c=javalaboratories-org.cer -f=secret-text.txt -e");
        arguments.parse(args);

        assertEquals(Mode.ENCRYPT, arguments.getModeValue());
    }

    @Test
    public void testPrintHelp_Pass() {
        arguments.printHelp(null);
    }

    private String[] toArgs(String commandSyntax) {
        Objects.requireNonNull(commandSyntax);
        return commandSyntax.split(" ");
    }

}
