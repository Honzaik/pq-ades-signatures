package xyz.honzaik;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pki.jaxb.model.JAXBCertEntityRepository;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class Benchmark
{

    private static int repetitions;
    private static int warmup;

    private static final Logger LOG = LoggerFactory.getLogger(Benchmark.class);

    private static String[] classicalPKIFileNames;
    private static String[] pqPKIFileNames;
    private static String[] compositePKIFileNames;
    private static HashMap<String, JAXBCertEntityRepository> allPKIs = new HashMap<>();

    private static FileWriter signingSpeedResultsFile;
    private static FileWriter sizeResultsFile;
    private static FileWriter verificationResultsFile;

    private static File validationPolicyFile;

    public static void main(String[] args) throws IOException
    {
        parseAndProcessArgs(args);

        setupBenchmark();

        String signerSubjectName = "Jan Oupický";

        long timestamp = System.currentTimeMillis();

        try
        {
            signingSpeedResultsFile = new FileWriter("AdES_benchmark_signing_" + (repetitions + warmup) + "_" + timestamp + ".txt");
            sizeResultsFile = new FileWriter("AdES_benchmark_size_" + (repetitions + warmup) + "_" + timestamp + ".txt");
            verificationResultsFile = new FileWriter("AdES_benchmark_verification_" + (repetitions + warmup) + "_" + timestamp + ".txt");

            for (String classicalPKIFileName : classicalPKIFileNames)
            {
                HashMap<PKIType, JAXBCertEntityRepository> pkis = new HashMap<>();
                pkis.put(PKIType.CLASSICAL, allPKIs.get(classicalPKIFileName));
                benchmarkSigner(pkis, SignerMode.CLASSICAL, signerSubjectName);
            }

            for (String pqPKIFileName : pqPKIFileNames)
            {
                HashMap<PKIType, JAXBCertEntityRepository> pkis = new HashMap<>();
                pkis.put(PKIType.PURELY_PQ, allPKIs.get(pqPKIFileName));
                benchmarkSigner(pkis, SignerMode.PURELY_PQ, signerSubjectName);
            }

            for (String compositePKIFileName : compositePKIFileNames)
            {
                HashMap<PKIType, JAXBCertEntityRepository> pkis = new HashMap<>();
                pkis.put(PKIType.COMPOSITE_HYBRID, allPKIs.get(compositePKIFileName));
                benchmarkSigner(pkis, SignerMode.COMPOSITE_HYBRID, signerSubjectName);

            }

            for (String classicalPKIFileName : classicalPKIFileNames)
            {
                for (String pqPKIFileName : pqPKIFileNames)
                {
                    HashMap<PKIType, JAXBCertEntityRepository> pkis = new HashMap<>();
                    pkis.put(PKIType.CLASSICAL, allPKIs.get(classicalPKIFileName));
                    pkis.put(PKIType.PURELY_PQ, allPKIs.get(pqPKIFileName));

                    benchmarkSigner(pkis, SignerMode.SEQUENTIAL_HYBRID, signerSubjectName);
                }
            }

            signingSpeedResultsFile.flush();
            signingSpeedResultsFile.close();
            sizeResultsFile.flush();
            sizeResultsFile.close();
            verificationResultsFile.flush();
            verificationResultsFile.close();
        }
        catch (IOException e)
        {
            throw new RuntimeException(e);
        }
    }

    private static void parseAndProcessArgs(String[] args)
    {
        if (args.length != 5) {
            System.err.println("5 arguments are required [warmup] [repetitions] [list;of;classical;pki] [list;of;pq;pki] [list;of;composite;pki]");
            System.exit(1);
        }
        warmup = Integer.parseInt(args[0]);
        repetitions = Integer.parseInt(args[1]);
        classicalPKIFileNames = args[2].split(";");
        pqPKIFileNames = args[3].split(";");
        compositePKIFileNames = args[4].split(";");

        LOG.info("Warmup: " + warmup);
        LOG.info("Reps: " + repetitions);
        LOG.info("Clasical: " + String.join(", ", classicalPKIFileNames));
        LOG.info("PQ: " + String.join(", ", pqPKIFileNames));
        LOG.info("Comp: " + String.join(", ", compositePKIFileNames));
    }

    private static String getPKIsName(Map<PKIType, JAXBCertEntityRepository> pkis)
    {
        String pkiName = "";
        for (PKIType pkiType : pkis.keySet())
        {
            pkiName += pkis.get(pkiType).getAll().get(0).getCertificateToken().getSignatureAlgorithm().getName();
            pkiName += "+";
        }
        return pkiName;
    }

    private static void setupBenchmark() throws IOException
    {
        LOG.info("began loading PKIs");
        for (String classicalPKIFileName : classicalPKIFileNames) {
            allPKIs.put(classicalPKIFileName, PKILoader.getPKI(classicalPKIFileName));
        }
        for (String pqPKIFileName : pqPKIFileNames) {
            allPKIs.put(pqPKIFileName, PKILoader.getPKI(pqPKIFileName));
        }
        for (String compositePKIFileName : compositePKIFileNames) {
            allPKIs.put(compositePKIFileName, PKILoader.getPKI(compositePKIFileName));
        }
        LOG.info("loaded PKIs");

        validationPolicyFile = Utils.getFileFromResource("/" + GlobalConstants.POLICIES_FOLDER + "/" + GlobalConstants.POLICY_FILENAME);
    }

    private static SignatureLevel[] getSigningLevels(SignatureFormat signatureFormat)
    {
        switch (signatureFormat) {
            case XAdES -> {
                return new SignatureLevel[]{SignatureLevel.XAdES_BASELINE_B, SignatureLevel.XAdES_BASELINE_T, SignatureLevel.XAdES_BASELINE_LT, SignatureLevel.XAdES_BASELINE_LTA};
            }
            case CAdES -> {
                return new SignatureLevel[]{SignatureLevel.CAdES_BASELINE_B, SignatureLevel.CAdES_BASELINE_T, SignatureLevel.CAdES_BASELINE_LT, SignatureLevel.CAdES_BASELINE_LTA};
            }
            case PAdES -> {
                return new SignatureLevel[]{SignatureLevel.PAdES_BASELINE_B, SignatureLevel.PAdES_BASELINE_T, SignatureLevel.PAdES_BASELINE_LT, SignatureLevel.PAdES_BASELINE_LTA};
            }
        }
        return null;
    }

    private static void benchmarkSigner(Map<PKIType, JAXBCertEntityRepository> pkis, SignerMode mode, String signerSubjectName) throws IOException
    {
        LOG.info("######################################");
        LOG.info("Benchmarking signer in mode " + mode.name() + " with PKI " + getPKIsName(pkis));
        Signer signer = new Signer(pkis, mode, signerSubjectName);

        String resultsHeader = mode.name() + "; " + signer.getPrimarySignatureAlgorithm().getName();
        if (mode == SignerMode.SEQUENTIAL_HYBRID)
        {
            resultsHeader += " + " + signer.getSecondarySignatureAlgorithm().getName();
        }
        resultsHeader += "; ";

        signingSpeedResultsFile.write(resultsHeader);
        sizeResultsFile.write(resultsHeader);
        verificationResultsFile.write(resultsHeader);

        for (SignatureFormat signatureFormat : SignatureFormat.values()) {
            if (signatureFormat == SignatureFormat.JAdES) {
                continue;
            }
            LOG.info("beginning " + signatureFormat.name());
            String inputFileName = "input.xml";
            if (signatureFormat == SignatureFormat.PAdES) {
                inputFileName = "input.pdf";
            }

            File inputFile = new File(GlobalConstants.INPUT_FOLDER + "/" + inputFileName);
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
            catch (IOException e)
            {
                throw new RuntimeException(e);
            }

            SignatureLevel[] signingLevels = getSigningLevels(signatureFormat);
            for (SignatureLevel signatureLevel : signingLevels) {
                //for sequential hybrid allow only LTA
                if (signer.getMode() == SignerMode.SEQUENTIAL_HYBRID && !(signatureLevel == SignatureLevel.XAdES_BASELINE_LTA || signatureLevel == SignatureLevel.CAdES_BASELINE_LTA || signatureLevel == SignatureLevel.PAdES_BASELINE_LTA)) {
                    signingSpeedResultsFile.write(";");
                    sizeResultsFile.write(";");
                    verificationResultsFile.write(";");
                    continue;
                }
                benchmarkSpecificSigning(signer, signatureFormat, signatureLevel, inputBytes);
            }
        }
        signingSpeedResultsFile.write("\n");
        signingSpeedResultsFile.flush();
        sizeResultsFile.write("\n");
        sizeResultsFile.flush();
        verificationResultsFile.write("\n");
        verificationResultsFile.flush();
        LOG.info("Signing benchmark finished");
    }

    private static void benchmarkSpecificSigning(Signer signer, SignatureFormat signatureFormat, SignatureLevel signatureLevel, byte[] inputBytes) throws IOException
    {
        int totalRepetitions = warmup + repetitions;
        long totalSize = 0;
        double[] dataPoints = new double[totalRepetitions];
        byte[] resultingBytes = null;
        for (int i = 0; i < totalRepetitions; i++) {
            double startTime = System.nanoTime();
            resultingBytes = signer.signFileBytes(inputBytes, signatureFormat, signatureLevel);
            dataPoints[i] = Math.round((System.nanoTime() - startTime)/100d)/10000d;
            totalSize += resultingBytes.length;
        }
        double[] signingTimeAverageAndStDev = Utils.getAverageAndStdev(dataPoints, warmup);
        long averageSize = totalSize / totalRepetitions;

        signingSpeedResultsFile.write(String.format("%.4f", signingTimeAverageAndStDev[0]) + " ± " + String.format("%.4f", signingTimeAverageAndStDev[1]) + "; ");
        sizeResultsFile.write(averageSize + "; ");

        //reuse last signedFile for verification bench
        CertificateVerifier verifier = signer.getCertificateVerifier();
        DSSDocument signatureToValidate = new InMemoryDocument(resultingBytes);

        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signatureToValidate);
        validator.setCertificateVerifier(verifier);

        for (int i = 0; i < totalRepetitions; i++) {
            double startTime = System.nanoTime();
            validator.validateDocument(validationPolicyFile);
            dataPoints[i] = Math.round((System.nanoTime() - startTime)/100d)/10000d;
        }
        double[] verificationTimeAverageAndStDev = Utils.getAverageAndStdev(dataPoints, warmup);
        verificationResultsFile.write(String.format("%.4f", verificationTimeAverageAndStDev[0]) + " ± " + String.format("%.4f", verificationTimeAverageAndStDev[1]) + "; ");

    }



}
