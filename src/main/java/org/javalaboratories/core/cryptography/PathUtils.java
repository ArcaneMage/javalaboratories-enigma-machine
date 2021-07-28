package org.javalaboratories.core.cryptography;

import java.nio.file.Path;
import java.nio.file.Paths;

public final class PathUtils {

    private PathUtils() {}

    public static Path truncateFileExt(Path path) {
        String s = path.toString();
        if (s.lastIndexOf(".") > 1) return Paths.get(s.substring(0,s.lastIndexOf(".")));
        else  return path;
    }
}
