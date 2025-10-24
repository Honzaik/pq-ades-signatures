package xyz.honzaik;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pki.jaxb.model.JAXBCertEntityRepository;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.HashMap;

public class Example
{
    private static final Logger LOG = LoggerFactory.getLogger(Example.class);

    private static SignatureFormat signatureFormat;
    private static SignatureLevel signatureLevel;
    private static SignerMode signerMode;
    private static File inputFile;

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException
    {
        parseArgs(args);

        //Note that shared PKI across signers
        HashMap<PKIType, JAXBCertEntityRepository> pkis = new HashMap<>();
        pkis.put(PKIType.CLASSICAL, PKILoader.getPKI(GlobalConstants.CLASSICAL_PKI_NAME));
        pkis.put(PKIType.PURELY_PQ, PKILoader.getPKI(GlobalConstants.PURELY_PQ_PKI_NAME));
        pkis.put(PKIType.COMPOSITE_HYBRID, PKILoader.getPKI(GlobalConstants.COMPOSITE_PKI_NAME));

        byte[] inputBytes;
        try
        {
            FileInputStream fileInputStream = new FileInputStream(inputFile);
            inputBytes = fileInputStream.readAllBytes();
            fileInputStream.close();
        }
        catch (FileNotFoundException e)
        {
            throw new RuntimeException(e);
        }

        Signer documentSigner = new Signer(pkis, signerMode, "Jan Oupický");
        byte[] resultingBytes = documentSigner.signFileBytes(inputBytes, signatureFormat, signatureLevel);

        File outputFile = new File(inputFile.getPath() + getOutputFileExtension(signatureFormat));
        FileOutputStream fileOutputStream = new FileOutputStream(outputFile);
        fileOutputStream.write(resultingBytes);
        fileOutputStream.close();

        LOG.info("@@@@@@@@@@@@@@@@@@@@@@@@");
        LOG.info("signature finished");
        LOG.info("beginning validation");
        Validator documentValidator = new Validator(pkis, signerMode);
        documentValidator.validateSignature(outputFile, null);
        LOG.info("validation completed");

    }

    private static void parseArgs(String[] args)
    {
        if (args.length != 3) {
            System.err.println("3 arguments are required [AdES format (xades,pades,cades,jades)] [signing mode (classical,purelypq,composite,sequential] [inputFilePath]");
            System.exit(1);
        }

        String format = args[0];
        String mode = args[1];
        String inputFilePath = args[2];

        switch (format) {
            case "xades" -> {
                signatureFormat = SignatureFormat.XAdES;
                signatureLevel = SignatureLevel.XAdES_BASELINE_LTA;
            }
            case "cades" -> {
                signatureFormat = SignatureFormat.CAdES;
                signatureLevel = SignatureLevel.CAdES_BASELINE_LTA;
            }
            case "pades" -> {
                signatureFormat = SignatureFormat.PAdES;
                signatureLevel = SignatureLevel.PAdES_BASELINE_LTA;
            }
//            case "jades" -> {
//                signatureFormat = SignatureFormat.JAdES;
//                signatureLevel = SignatureLevel.JAdES_BASELINE_LTA;
//            }
            default -> throw new IllegalArgumentException("Unknown format: " + format);
        }

        switch (mode) {
            case "classical" -> signerMode = SignerMode.CLASSICAL;
            case "purelypq" -> signerMode = SignerMode.PURELY_PQ;
            case "composite" -> signerMode = SignerMode.COMPOSITE_HYBRID;
            case "sequential" -> signerMode = SignerMode.SEQUENTIAL_HYBRID;
            default -> throw new IllegalArgumentException("Unknown mode: " + mode);
        }

       inputFile = new File(inputFilePath);

        if (!inputFile.exists()) {
            throw new IllegalArgumentException("Input file does not exist: " + inputFilePath);
        }
    }

    private static String getOutputFileExtension(SignatureFormat signatureFormat) {
        switch (signatureFormat) {
            case XAdES: return ".signed.xml";
            case CAdES: return ".signed.p12";
            case PAdES: return ".signed.pdf";
//            case JAdES: return ".signed.json";
        }
        throw new IllegalArgumentException("Unknown signature format: " + signatureFormat);
    }
}

