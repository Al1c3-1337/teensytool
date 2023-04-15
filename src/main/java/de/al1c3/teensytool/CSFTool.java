package de.al1c3.teensytool;

import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.PrivateKey;
import java.util.Map;

import static de.al1c3.teensytool.Utils.concatAll;

public class CSFTool {

    private final byte[] certBytes;
    private final BCRSAPublicKey pubkey;

    private final X509CertificateHolder ch;

    private final PrivateKey privateKey;

    /**
     * Create new CSFTool instance
     *
     * @param certdata PEM-formatted certificate
     * @param keydata PEM-formatted private key
     * @param password password for private key
     * @throws IOException If anything goes wrong
     */
    public CSFTool(byte[] certdata, byte[] keydata, String password) throws IOException {
        this.certBytes = new PemReader(new InputStreamReader(new ByteArrayInputStream(certdata))).readPemObject().getContent();
        Certificate cert = Certificate.getInstance(certBytes);
        this.pubkey = (BCRSAPublicKey) BouncyCastleProvider.getPublicKey(cert.getSubjectPublicKeyInfo());
        this.ch = new X509CertificateHolder(cert);
        PEMParser parser = new PEMParser(new PemReader(new InputStreamReader(new ByteArrayInputStream(keydata))));
        PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(password.toCharArray());
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        this.privateKey = converter.getKeyPair(((PEMEncryptedKeyPair)parser.readObject()).decryptKeyPair(decProv)).getPrivate();
    }
    private void insertSize(byte[] data) {
        byte size0 = (byte)(data.length >> 8);
        byte size1 = (byte)(data.length);
        data[1] = size0;
        data[2] = size1;
    }

    private void insertSize(byte[] data, int size) {
        byte size0 = (byte)(size >> 8);
        byte size1 = (byte)(size);
        data[1] = size0;
        data[2] = size1;
    }

    /**
     * Create CSF data
     *
     * @param dataToSign Data to be signed
     * @param startAddr Starting address of the signed data in target memory
     * @return Signed CSF
     * @throws IOException
     * @throws OperatorCreationException
     * @throws CMSException
     */
    public byte[] makeCsf(byte[] dataToSign, int startAddr) throws IOException, OperatorCreationException, CMSException {
        byte[] csfHeader = new byte[4];
        csfHeader[0] = (byte)0xD4;
        csfHeader[3] = (byte)0x40;

        byte[] csfInstallKey = new byte[12];
        csfInstallKey[0] = (byte) 0xBE;
        csfInstallKey[4] = (byte) 0x03;
        csfInstallKey[5] = (byte) 0x17;
        // length of complete csf header in csfInstallKey[8 - 11]
        insertSize(csfInstallKey);

        byte[] csfAuthData1 = new byte[12];
        csfAuthData1[0] = (byte) 0xCA;
        csfAuthData1[4] = (byte) 0x01;
        csfAuthData1[5] = (byte) 0xC5;
        // length of PARTOFCSF as offset for authentication data csfAuthData1[8 - 11]
        insertSize(csfAuthData1);

        byte[] csfAuthData2 = new byte[20];
        csfAuthData2[0] = (byte) 0xCA;
        csfAuthData2[5] = (byte) 0xC5;
        // length of PARTOFCSF as offset for authentication data csfAuthData2[8 - 11]
        csfAuthData2[12] = (byte)(startAddr >> 24);
        csfAuthData2[13] = (byte)(startAddr >> 16);
        csfAuthData2[14] = (byte)(startAddr >> 8);
        csfAuthData2[15] = (byte)(startAddr);
        csfAuthData2[16] = (byte)(dataToSign.length >> 24);
        csfAuthData2[17] = (byte)(dataToSign.length >> 16);
        csfAuthData2[18] = (byte)(dataToSign.length >> 8);
        csfAuthData2[19] = (byte)(dataToSign.length);
        insertSize(csfAuthData2);

        // Unlock command to enable SNVS ZMK_SET and SW_RESET, can be extended at will, See HAB4_API.pdf from cst.
        byte[] csfAdditionalData = Hex.decode("B200081E00000003");

        int headSize = csfHeader.length + csfInstallKey.length + csfAuthData1.length + csfAuthData2.length + csfAdditionalData.length;
        insertSize(csfHeader, headSize);

        csfInstallKey[8] = (byte)(headSize >> 24);
        csfInstallKey[9] = (byte)(headSize >> 16);
        csfInstallKey[10] = (byte)(headSize >> 8);
        csfInstallKey[11] = (byte)(headSize);




        byte[] N = pubkey.getModulus().toByteArray();
        if (N[0] == 0) {
            byte[] tmp = new byte[N.length - 1];
            System.arraycopy(N, 1, tmp, 0, tmp.length);
            N = tmp;
        }
        byte[] e = pubkey.getPublicExponent().toByteArray();

        byte[] csfCert1 = new byte[16 + N.length + e.length];
        csfCert1[0] = (byte) 0xD7;
        csfCert1[1] = (byte)(csfCert1.length >> 8);
        csfCert1[2] = (byte)(csfCert1.length);
        csfCert1[3] = (byte) 0x40;
        csfCert1[4] = (byte) 0xE1;
        csfCert1[5] = (byte)((csfCert1.length - 4) >> 8);
        csfCert1[6] = (byte)(csfCert1.length - 4);
        csfCert1[7] = (byte) 0x21;
        csfCert1[12] = (byte)(((N.length * 8)) >>> 11);
        csfCert1[13] = (byte)(((N.length * 8)) >>> 3);
        csfCert1[14] = (byte)(((e.length * 8)) >>> 11);
        csfCert1[15] = (byte)(((e.length * 8)) >>> 3);
        System.arraycopy(N,0,csfCert1,16,N.length);
        System.arraycopy(e,0,csfCert1,16 + N.length,e.length);

        byte[] padding0 = new byte[1]; //TODO: Remove and put in real alignment of 4

        byte[] csfCert2 = new byte[certBytes.length + 4];
        csfCert2[0] = (byte) 0xD7;
        csfCert2[3] = (byte) 0x40;
        System.arraycopy(certBytes,0,csfCert2,4,certBytes.length);
        insertSize(csfCert2);

        byte[] padding1 = new byte[2]; //TODO: Remove and put in real alignment of 4

        int authSize1 = csfHeader.length + csfInstallKey.length + csfAuthData1.length + csfAuthData2.length + csfAdditionalData.length + csfCert1.length + padding0.length + csfCert2.length + padding1.length;
        csfAuthData1[8] = (byte)(authSize1 >> 24);
        csfAuthData1[9] = (byte)(authSize1 >> 16);
        csfAuthData1[10] = (byte)(authSize1 >> 8);
        csfAuthData1[11] = (byte)(authSize1);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(privateKey);
        SignerInfoGenerator sigGen = new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                .build(sha1Signer, ch);

        final CMSAttributeTableGenerator sAttrGen = sigGen.getSignedAttributeTableGenerator();
        sigGen = new SignerInfoGenerator(sigGen, new
                DefaultSignedAttributeTableGenerator(){
                    @Override
                    public AttributeTable getAttributes(
                            Map parameters) {
                        AttributeTable ret = sAttrGen.getAttributes(parameters);
                        return ret.remove(CMSAttributes.cmsAlgorithmProtect);
                    }
                }, sigGen.getUnsignedAttributeTableGenerator());
        gen.addSignerInfoGenerator(sigGen);

        CMSSignedData sigData = gen.generate(new CMSProcessableByteArray(concatAll(csfHeader,csfInstallKey,csfAuthData1,csfAuthData2,csfAdditionalData)), false);
        byte[] sigTemp = sigData.getEncoded();
        byte[] csfSigData1 = new byte[4+sigTemp.length];
        csfSigData1[0] = (byte) 0xD8;
        csfSigData1[3] = (byte) 0x40;
        System.arraycopy(sigTemp,0,csfSigData1,4,sigTemp.length);
        insertSize(csfSigData1);

        CMSSignedData sigData2 = gen.generate(new CMSProcessableByteArray(dataToSign), false);
        byte[] sigTemp2 = sigData2.getEncoded();
        byte[] csfSigData2 = new byte[4+sigTemp2.length];
        csfSigData2[0] = (byte) 0xD8;
        csfSigData2[3] = (byte) 0x40;
        System.arraycopy(sigTemp2,0,csfSigData2,4,sigTemp2.length);
        insertSize(csfSigData2);


        int authSize2 = csfHeader.length + csfInstallKey.length + csfAuthData1.length + csfAuthData2.length + csfAdditionalData.length + csfCert1.length + padding0.length + csfCert2.length + padding1.length + csfSigData1.length;
        csfAuthData2[8] = (byte)(authSize2 >> 24);
        csfAuthData2[9] = (byte)(authSize2 >> 16);
        csfAuthData2[10] = (byte)(authSize2 >> 8);
        csfAuthData2[11] = (byte)(authSize2);


        sigData = gen.generate(new CMSProcessableByteArray(concatAll(csfHeader,csfInstallKey,csfAuthData1,csfAuthData2,csfAdditionalData)), false);
        byte[] sigTemp1 = sigData.getEncoded();
        if (sigTemp.length != sigTemp1.length)
            throw new IOException("Signature length mismatch");
        System.arraycopy(sigTemp1,0,csfSigData1,4,sigTemp1.length);
        return concatAll(csfHeader,csfInstallKey,csfAuthData1,csfAuthData2,csfAdditionalData,csfCert1,padding0,csfCert2,padding1,csfSigData1,csfSigData2);
    }
}
