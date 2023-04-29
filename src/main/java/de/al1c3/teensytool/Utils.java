package de.al1c3.teensytool;

import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.*;
import java.net.URL;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

@SuppressWarnings("unused")
public class Utils {
    public static byte[] toByteArray(int value) {
        return  ByteBuffer.allocate(4).putInt(value).array();
    }

    public static byte[] toByteArray(long value) {
        return  ByteBuffer.allocate(8).putLong(value).array();
    }

    /**
     * Insert integer into byte array as big endian
     *
     * @param array Byte array
     * @param offset Offset, where to store the integer
     * @param data int
     */
    public static void insertIntBE(byte[] array, int offset, int data) {
        array[offset]     = (byte)(data >> 24);
        array[offset + 1] = (byte)(data >> 16);
        array[offset + 2] = (byte)(data >> 8);
        array[offset + 3] = (byte)(data);
    }

    /**
     * Insert integer into byte array as little endian
     *
     * @param array Byte array
     * @param offset Offset, where to store the integer
     * @param data int
     */
    public static void insertIntLE(byte[] array, int offset, int data) {
        array[offset]     = (byte)(data);
        array[offset + 1] = (byte)(data >> 8);
        array[offset + 2] = (byte)(data >> 16);
        array[offset + 3] = (byte)(data >> 24);
    }

    /**
     * Extract integer from byte array as big endian
     *
     * @param array Byte array
     * @param offset Offset of integer
     * @return int
     */
    public static int extractIntBE(byte[] array, int offset) {
        return ((array[offset] << 24) | (array[offset + 1] << 16) | (array[offset + 2] << 8) | array[offset +3]);
    }

    /**
     * Extract integer from byte array as little endian
     *
     * @param array Byte array
     * @param offset Offset of integer
     * @return int
     */
    public static int extractIntLE(byte[] array, int offset) {
        return ((ub(array[offset])) | (ub(array[offset + 1]) << 8) | (ub(array[offset + 2]) << 16) | ub(array[offset + 3]) << 24);
    }

    /**
     * Reverse bytes in byte array. Useful for endianess conversion.
     *
     * @param byteArray Byte array to reverse
     * @return Reversed byte array
     */
    public static byte[] reverse (byte[] byteArray) {
        byte[] rev = new byte[byteArray.length];
        for (int i = 0; i < byteArray.length; i++)
            rev[byteArray.length - (i + 1)] = byteArray[i];
        return rev;
    }

    /**
     * Concat as many byte arrays as you wish.
     *
     * @param bytes Byte arrays
     * @return Concatenated byte array
     */
    public static byte[] concatAll(byte[] ... bytes) {
        byte[] tmp = new byte[0];
        for (byte[] bx : bytes) {
            tmp = Arrays.concatenate(tmp,bx);
        }
        return tmp;
    }

    /**
     * Turn signed byte into unsigned int
     *
     * @param b byte
     * @return int
     */
    private static int ub(byte b) {
        return b & 0xff;
    }

    /**
     * Divide byte array in chunks
     *
     * @param source Data to split
     * @param chunksize Macimum chunk size
     * @return List of data chunks
     */
    public static List<byte[]> divideArray(byte[] source, int chunksize) {

        List<byte[]> result = new ArrayList<byte[]>();
        int start = 0;
        while (start < source.length) {
            int end = Math.min(source.length, start + chunksize);
            result.add(Arrays.copyOfRange(source, start, end));
            start += chunksize;
        }

        return result;
    }

    /**
     * Read a linear (even non-continuous) Intel-HEX file
     *
     * @param filename Filename of Intel-HEX file
     * @param addrOut Start address as AtomicInteger
     * @return Binary contents of file
     * @throws IOException
     */
    public static byte[] readHexFile (String filename, AtomicInteger addrOut) throws IOException {
        BufferedReader bf = new BufferedReader(new InputStreamReader(new FileInputStream(filename)));
        List<Byte> bytes = new ArrayList<>();
        int startAddress = 0;
        boolean addrRead = false;
        int tmpAddr = 0;
        int currentAddr = 0;
        readerloop: while(bf.ready()) {
            IntelHexRecord ihr = IntelHexRecordReader.readRecord(bf.readLine());
            switch (ihr.getRecordType()) {
                case IntelHexRecord.EXTENDED_LINEAR_ADDRESS_RECORD_TYPE:
                    tmpAddr = ub(ihr.getData()[0]) << 24 | ub(ihr.getData()[1]) << 16;
                    break;
                case IntelHexRecord.DATA_RECORD_TYPE:
                    if (!addrRead) {
                        startAddress = tmpAddr | ihr.getLoadOffset();
                        currentAddr = startAddress;
                        addrRead = true;
                    }
                    if (currentAddr < (tmpAddr | ihr.getLoadOffset())) {
                        while (currentAddr < (tmpAddr | ihr.getLoadOffset())) {
                            bytes.add((byte)0x00); //TODO: check filler byte
                            currentAddr++;
                        }
                    }
                    for (byte b : ihr.getData()) {
                        bytes.add(b);
                        currentAddr++;
                    }
                    break;
                case IntelHexRecord.END_OF_FILE_RECORD_TYPE:
                    break readerloop;
            }
        }
        bf.close();
        Byte[] dataTmp = bytes.toArray(Byte[]::new);
        addrOut.set(startAddress);
        return ArrayUtils.toPrimitive(dataTmp);
    }

    /**
     * Write continuous Intel-HEX file
     *
     * @param addr Start address
     * @param data Data to be put in file
     * @return Intel-HEX file as string
     * @throws IOException
     */
    public static String makeHexFile(int addr, byte[] data) throws IOException {
        StringBuilder sb = new StringBuilder();
        IntelHexRecordWriter ihrw = new IntelHexRecordWriter(0x20,addr);
        for (byte b : data)
            ihrw.addByte(b);
        for (IntelHexRecord ihr : ihrw.finish()) {
            sb.append(ihr.format());
            sb.append("\r\n");
        }
        return sb.toString();
    }

    /**
     * Decrypt and extract extremely wrongly formatted symmetric encryption key from PEM
     *
     * @param encryptedKey PEM-formatted encrypted and "specially encoded" symmetric key
     * @param password Password to decrypt key
     * @return Symmetric encryption key
     * @throws IOException
     * @throws OperatorCreationException
     * @throws PKCSException
     */
    public static byte[] extractXDHFormattedAESKey(byte[] encryptedKey, String password) throws IOException, OperatorCreationException, PKCSException {
        PEMParser parser = new PEMParser(new PemReader(new InputStreamReader(new ByteArrayInputStream(encryptedKey))));
        InputDecryptorProvider decProv = new JceOpenSSLPKCS8DecryptorProviderBuilder().build(password.toCharArray());
        byte[] encKey = ((PKCS8EncryptedPrivateKeyInfo)parser.readObject()).decryptPrivateKeyInfo(decProv).getPrivateKey().getEncoded();
        ASN1OctetString os = ASN1OctetString.getInstance(ASN1OctetString.getInstance(encKey).getOctets());
        return Arrays.copyOf(os.getOctets(),0x10);
    }

    public static byte[] downloadUrl(URL toDownload) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        try {
            byte[] chunk = new byte[4096];
            int bytesRead;
            InputStream stream = toDownload.openStream();

            while ((bytesRead = stream.read(chunk)) > 0) {
                outputStream.write(chunk, 0, bytesRead);
            }
            stream.close();

        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }

        return outputStream.toByteArray();
    }
}
