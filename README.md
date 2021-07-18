# javalaboratories-enigma-machine

## Introduction
This utility enables asymmetric encryption and decryption. To use this utility requires compilation, configuration
of key pairs, and it's ready for use.

## Maven Build

`Enigma Machine` is a maven project and so the initial step is to download and install the Apache Maven Project.
It is available from [here](http://maven.apache.org/download.cgi?src=www.discoversdk.com). Afterwards, consider to 
clone or download this repository and then build, steps are as follows:
```
    cd <project-directory>
    git clone https://github.com/ArcaneMage/javalaboratories-enigma-machine.git
    
    mvn clean verify   
```
A series of artifacts and dependencies are downloaded to your git cache locally on your filesystem. This is
normal behaviour and only occurs once. However, if the build displays something like the following text below, then 
consider it to be successful and follow the `Installation Notes`.
```
[INFO] --- maven-antrun-plugin:3.0.0:run (default) @ javalaboratories-enigma-machine ---
[INFO] Executing tasks
[INFO]      [copy] Copying 1 file to /Users/henryk/Projects/java/javalaboratories-enigma-machine/software-artifacts/javalaboratories-enigma-machine/bin
[INFO]      [copy] Copying 1 file to /Users/henryk/Projects/java/javalaboratories-enigma-machine/software-artifacts/javalaboratories-enigma-machine/lib
[INFO]     [mkdir] Created dir: /Users/henryk/Projects/java/javalaboratories-enigma-machine/software-artifacts/javalaboratories-enigma-machine/config
[INFO]       [zip] Building zip: /Users/henryk/Projects/java/javalaboratories-enigma-machine/javalaboratories-enigma-machine.zip
[INFO]    [delete] Deleting directory /Users/henryk/Projects/java/javalaboratories-enigma-machine/software-artifacts
[INFO] Executed tasks
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
[INFO] Total time: 9.294 s
[INFO] Finished at: 2021-07-18T09:03:27+01:00
[INFO] Final Memory: 26M/1098M
[INFO] ------------------------------------------------------------------------
```
## Installation Notes
From the build step above, the `javalaboratories-enigma-machine.zip` is created. This is effectively the software
package to be installed. Decide on a suitable location to install the package, on some Linux systems this could
be the `$HOME/opt` directory, but the installation location is entirely up to the user.

```
    cp javalaboratories-enigma-machine.zip $HOME/opt
    cd $HOME/opt
    unzip javalaboratories-enigma-machine.zip
    chmod 750 javalaboratories-enigma-machine/bin/enigma-machine
```
### Configuration
Now that the application is installed, it is time to configure it with a keypair, ie: public and private keys. Achieving
this involves leveraging a keystore called `keys-vault.jks` (although this can be any keystore, this is the default one)
The following steps illustrates how to create the keystore and make it the default keystore to reference during decryption
phase.
```
keytool -genkeypair -v -alias javalaboratories-org -keysize 2048 -validity 10950 -keystore keys-vault.jks -storepass changeit -keyalg RSA    

```
*NB: A brief note on the private key alias: `javalaboratories-org` is the default, which means it doesn't have to be
specified with the `-v` argument. Future versions of the application will support multiple default aliases.*

The `keytool` will ask several questions for the public certificate, but make sure the `private key` password is **NOT** 
the same as the `storepass` parameter -- keep this password in a safe place. Once the `keys-vault.jks` file is created,
extracting the public certificate is straight forward:
```
keytool -rfc -v -exportcert -alias javalaboratories-org -file javalaboratories-org.cer -keystore keys-vault.jks
```
This file can be issued to anybody for encryption purposes, but **DO NOT** inform them the `private key` password. Next 
step is to copy the `keys-vault.jks` file to the `config` directory in the installation, ie: `$HOME/opt/javalaboratories-enigma-machine/config`. 
The final step in this configuration is the environment variable `EM_HOME` to be set in the operating system's user profile:
```
# ENIGMA MACHINE
export EM_HOME=~/opt/javalaboratories-enigma-machine
PATH=$PATH:$EM_HOME/bin
```
### Usage
```
// Encryption
enigma-machine -c=javalaboratories-org.cer -f=<file> -e

// Decryption
enigma-machine -p=<private-key-password> -f=<encrypted-file> -d 
```
For complete help on usage, use the `-h` switch for details.
```
usage: enigma-machine [--encrypt --certificate=<arg>] | [--decrypt --private-key-password=<arg>]
                      [--output-file=<arg>] -file=<arg>
 -a,--private-key-alias <arg>      Private keys alias, default name "private-key-alias"
 -c,--certificate <arg>            Public certificate file
 -d,--decrypt                      Decrypt file
 -e,--encrypt                      Encrypt file
 -f,--file <arg>                   File to encrypt/decrypt
 -h                                Help
 -o,--output-file <arg>            Output filepath, default name is "<file>._encrypted" |
                                   "<file>._decrypted", depending on mode
 -p,--private-key-password <arg>   Private keys password
 -v,--vault <arg>                  Private keys vault, default name "keys-vault.jks"
```

## License
Licensed under the Apache License, Version 2.0 (the "License")

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an 
"AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language 
governing permissions and limitations under the License.
