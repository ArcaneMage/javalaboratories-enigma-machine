package org.javalaboratories.core.cryptography.model.yaml;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class KeyStore {
    String password;
    String privateKeyAlias;
    String file;
}
