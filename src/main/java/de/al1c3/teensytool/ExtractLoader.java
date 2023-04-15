package de.al1c3.teensytool;

import de.al1c3.teensytool.arduinopackage.Tool;
import com.github.zafarkhaja.semver.Version;
import com.google.gson.Gson;
import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.ArchiveInputStream;
import org.apache.commons.compress.archivers.ArchiveStreamFactory;
import org.apache.commons.compress.compressors.CompressorInputStream;
import org.apache.commons.compress.compressors.CompressorStreamFactory;
import org.bouncycastle.util.encoders.Hex;
import de.al1c3.teensytool.arduinopackage.PackageIndex;
import de.al1c3.teensytool.arduinopackage.Platform;
import de.al1c3.teensytool.arduinopackage.ToolsDependency;
import org.riversun.finbin.BinarySearcher;

import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import static de.al1c3.teensytool.Utils.*;

public class ExtractLoader {

    private static PackageIndex fetchPackages() throws Exception {
        byte[] packages = downloadUrl(new URL("https://www.pjrc.com/teensy/package_teensy_index.json"));
        Gson gson = new Gson();
        return gson.fromJson(new String(packages, StandardCharsets.UTF_8), PackageIndex.class);
    }

    private static byte[] getNewestTeensySecure() throws Exception {
        PackageIndex packageIndex = fetchPackages();
        List<Platform> platforms = packageIndex.packages.get(0).platforms;
        Platform newestNonBeta = platforms.stream().sorted((p1, p2) -> Version.valueOf(p2.version).compareTo(Version.valueOf(p1.version))).findFirst().get();
        Platform newest = platforms.get(platforms.size() - 1);
        System.out.println("Newest package: " + newest.version);
        //System.out.println("Newest non-beta: " + newestNonBeta.version);
        ToolsDependency toolsDependency = newest.toolsDependencies.stream().filter(td -> td.name.equals("teensy-tools")).findFirst().get();
        System.out.println("Tools version: " + toolsDependency.version);
        Tool tool = packageIndex.packages.get(0).tools.stream().filter(t -> t.name.equals("teensy-tools") && t.version.equals(toolsDependency.version)).findFirst().get();
        String toolURL = tool.systems.stream().filter(system -> system.host.equalsIgnoreCase("i686-mingw32")).findFirst().get().url;
        System.out.println("Tools URL: " + toolURL);
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final CompressorInputStream in = new CompressorStreamFactory().createCompressorInputStream(new ByteArrayInputStream(Utils.downloadUrl(new URL(toolURL))));
        final BufferedInputStream bis = new BufferedInputStream(in);
        final ArchiveInputStream tarIn = new ArchiveStreamFactory().createArchiveInputStream(bis);
        try {
            ArchiveEntry tarEntry = tarIn.getNextEntry();
            while (tarEntry != null) {
                if (tarEntry.getName().endsWith("teensy_secure.exe")) {
                    byte[] btoRead = new byte[1024];
                    BufferedOutputStream bout = new BufferedOutputStream(baos);
                    int len = 0;
                    while ((len = tarIn.read(btoRead)) != -1) {
                        bout.write(btoRead, 0, len);
                    }
                    bout.close();
                }
                tarEntry = tarIn.getNextEntry();
            }
            tarIn.close();
        }
        catch (IOException e) {
            throw new IOException("Could not get blobs from teensy_secure.exe", e);
        }
        baos.close();
        return baos.toByteArray();
    }

    public static void extractNewestTeensySecure() throws Exception {
        byte[] teensySecure = getNewestTeensySecure();
        byte[] loaderHeader = Hex.decode("D1002040");
        int lenLoader = extractIntLE(teensySecure,0x3614);
        BinarySearcher searcher = new BinarySearcher();
        int offsetLoader = searcher.indexOf(teensySecure, loaderHeader);
        int offsetHAB = offsetLoader - 0xA0;
        int lenHAB = 0x90;
        byte[] loader = Arrays.copyOfRange(teensySecure,offsetLoader, offsetLoader + lenLoader);
        byte[] hab = Arrays.copyOfRange(teensySecure,offsetHAB, offsetHAB + lenHAB);
        FileOutputStream fos = new FileOutputStream("teensy_secure_loader.bin");
        fos.write(loader);
        fos.close();
        fos = new FileOutputStream("teensy_secure_hab.bin");
        fos.write(hab);
        fos.close();
    }
}
