package de.al1c3.teensytool;

import java.io.File;
import java.nio.file.Files;
import java.util.concurrent.atomic.AtomicInteger;

public class Main {
    public static void main(String[] args) throws Exception {
        if (!new File("teensy_secure_hab.bin").exists() || !new File("teensy_secure_loader.bin").exists()) {
            System.out.println("Loader or HAB missing. Downloading and extracting to current directory...");
            try {
                ExtractLoader.extractNewestTeensySecure();
            }
            catch (Exception e) {
                System.out.println("Failed to download loader and HAB. Please download and extract manually from teensy_secure.exe and put it into teensy_secure_loader.bin and teensy_secure_hab.bin in the current directory. See https://www.pjrc.com/teensy/td_download.html");
                return;
            }
        }
        byte[] loader = Files.readAllBytes(new File("teensy_secure_loader.bin").toPath());
        byte[] hab = Files.readAllBytes(new File("teensy_secure_hab.bin").toPath());
        if (args.length != 1 && args.length != 2 && args.length != 3) {
            System.out.println("Usage: java -jar teensy-secure-uploader.jar <key.pem> <program.hex> [output.ehex] | <COM port>");
            return;
        }
        if (args.length == 1) {
            TeensyReboot.rebootTeensySerial(args[0]);
            return;
        }
        byte[] key = Files.readAllBytes(new File(args[0]).toPath());
        AtomicInteger addr = new AtomicInteger();
        byte[] program = Utils.readHexFile(args[1], addr);
        TeensySecureUploader teensySecureUploader = TeensySecureUploader.fromKeyPem(key);
        if (args.length == 3) {
            teensySecureUploader.writeEHex(program, addr.get(), loader, hab, args[2]);
        } else {
            //TODO: Use Reboot script if possible
            teensySecureUploader.uploadProgram(program, addr.get(), loader, hab);
        }
    }
}
