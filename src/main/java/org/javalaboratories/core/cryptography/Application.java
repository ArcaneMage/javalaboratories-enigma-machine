package org.javalaboratories.core.cryptography;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

public final class Application {

    private static final Logger logger = LoggerFactory.getLogger(Application.class);

    public static void main(String[] args) {
        CommandLineArguments arguments = new DefaultCommandLineArguments();
        if ( Arrays.stream(args).anyMatch(p-> p.contains("-h")) )
            arguments.printHelp(null);
        else {
            ApplicationBuildInformation build = new ApplicationBuildInformation();
            logger.info("\nEnigma Machine v{}, build ({})",build.getVersion(), build.getTimestamp());
            logger.info("Java Laboratories, Kevin Henry (c) 2021\n");
            if ( arguments.parse(args)
                    .onFailure(s -> logger.error("Syntax error: {}",s.getMessage()))
                    .fold(f -> false, f -> true) ) {
                EnigmaMachine machine = new EnigmaMachine(arguments);
                if (!machine.execute())
                    System.exit(1);
                logger.info("Completed successfully");
            }
        }
    }
}
