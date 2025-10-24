package xyz.honzaik;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.AbstractSignatureParameters;
import eu.europa.esig.dss.signature.AbstractSignatureService;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * Helper static class containing various functions.
 */

public class Utils
{
    //we need to use getResourceAsStream because of JAR packing

    /**
     * Loads a file from resources into a temporary file.
     * @param resourcePath Relative path in the resource folder.
     * @return The loaded temporary file.
     * @throws IOException
     */
    public static File getFileFromResource(String resourcePath) throws IOException
    {
        InputStream inputStream = Utils.class.getResourceAsStream(resourcePath);
        if (inputStream == null)
        {
            throw new FileNotFoundException("Resource not found: " + resourcePath);
        }

        // Create a temporary file
        File tempFile = Files.createTempFile("resource-", ".xml").toFile();
        tempFile.deleteOnExit();

        // Copy resource content to the temp file
        try (FileOutputStream outStream = new FileOutputStream(tempFile))
        {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1)
            {
                outStream.write(buffer, 0, bytesRead);
            }
        }

        return tempFile;
    }

    /**
     * Computation of average and standard deviation of an array of values.
     * @param values
     * @param warmup Do not include the first [warmup] results into the computation.
     * @return
     */
    public static double[] getAverageAndStdev(double[] values, int warmup)
    {
        double[] result = new double[2];
        double total = 0;
        int length = values.length;
        for (int i = warmup; i < length; i++)
        {
            total += values[i];
        }

        result[0] = total / (length - warmup);

        double squaresSum = 0;
        for (int i = warmup; i < length; i++)
        {
            squaresSum += Math.pow(values[i] - result[0], 2);
        }

        result[1] = Math.sqrt(squaresSum / (length - warmup - 1)); //-1 unbiased estimate

        return result;
    }

    // archive timestamp is separate field and usually needs 1/2 to 3/5 of the size
    // for SLH-DSA
    // for 128s 60000 enough
    // for 128f 110000 enough
    // for 256s 190000 enough
    // for 256f 310000 enough
    // otherwise 30000 seems fine for ML-DSA-44

    /**
     * For PAdES we need to estimate in advance the resulting signature size.
     * This method contains some hardcoded values that work based on our experiments.
     * The relevant factor is the size of the public key and the signature.
     * The size needs to take into account all the components of the AdES signature such as certificates, revocation values etc.
     * @param signatureAlgorithm Signature algorithm that is going to be used.
     * @return int array of size 2, first value corresponds to the "main" AdES signature and the second to the archival timestamp if applied.
     */
    public static int[] getPDFContentSizes(SignatureAlgorithm signatureAlgorithm) {
        switch (signatureAlgorithm) {
            case SLH_DSA_SHA2_128S, SLH_DSA_SHAKE_128S ->
            {
                return new int[]{60000, 30000};
            }
            case SLH_DSA_SHA2_128F, SLH_DSA_SHAKE_128F ->
            {
                return new int[]{110000, 60000};
            }
            case SLH_DSA_SHA2_256S, SLH_DSA_SHAKE_256S ->
            {
                return new int[]{190000, 100000};
            }
            case SLH_DSA_SHA2_256F, SLH_DSA_SHAKE_256F ->
            {
                return new int[]{310000, 160000};
            }
            case ML_DSA_44, ML_DSA_44_ECDSA_P256_SHA256 ->
            {
                return new int[]{26000, 15000};
            }
            case ML_DSA_65, ML_DSA_65_ECDSA_P384_SHA512 ->
            {
                return new int[]{35000, 20000};
            }
            case ML_DSA_87, ML_DSA_87_ECDSA_P384_SHA512 ->
            {
                return new int[]{45000, 25000};
            }
            default -> { //classical ECDSA with P256
                return new int[]{5000, 3000};
            }
        }
    }

    /**
     * Returns a corresponding signature service based on the chosen signature format.
     * @param format AdES format
     * @param certificateVerifier corresponding certificate verifier
     * @return
     */
    public static AbstractSignatureService getSignatureService(SignatureFormat format, CertificateVerifier certificateVerifier)
    {
        switch (format)
        {
            case XAdES ->
            {
                return new XAdESService(certificateVerifier);
            }
            case CAdES ->
            {
                return new CAdESService(certificateVerifier);
            }
            case PAdES ->
            {
                return new PAdESService(certificateVerifier);
            }
            case JAdES ->
            {
                return new JAdESService(certificateVerifier);
            }
            default ->
            {
                return null;
            }
        }
    }

    /**
     * This returns a list of supported signature algorithms for the certificate verifier (DSS calls them encryption algorithms...)
     * Specifically, the signatures supported within revocation data.
     * The first argument in the list is the signature and the second is the minimal key size which is redundant for PQ algorithms.
     * @return
     */
    public static Map<EncryptionAlgorithm, Integer> getAllowedEncryptionAlgorithms()
    {
        Map<EncryptionAlgorithm, Integer> encryptionAlgos = new HashMap<>();
        encryptionAlgos.put(EncryptionAlgorithm.ML_DSA_44, 32);
        encryptionAlgos.put(EncryptionAlgorithm.ML_DSA_65, 32);
        encryptionAlgos.put(EncryptionAlgorithm.ML_DSA_87, 32);
        encryptionAlgos.put(EncryptionAlgorithm.ML_DSA_44_ECDSA_P256_SHA256, 32);
        encryptionAlgos.put(EncryptionAlgorithm.ML_DSA_65_ECDSA_P384_SHA512, 32);
        encryptionAlgos.put(EncryptionAlgorithm.ML_DSA_87_ECDSA_P384_SHA512, 32);
        encryptionAlgos.put(EncryptionAlgorithm.SLH_DSA_SHA2_128S, 32);
        encryptionAlgos.put(EncryptionAlgorithm.SLH_DSA_SHA2_128F, 32);
        encryptionAlgos.put(EncryptionAlgorithm.SLH_DSA_SHA2_256S, 32);
        encryptionAlgos.put(EncryptionAlgorithm.SLH_DSA_SHA2_256F, 32);
        encryptionAlgos.put(EncryptionAlgorithm.SLH_DSA_SHAKE_128S, 32);
        encryptionAlgos.put(EncryptionAlgorithm.SLH_DSA_SHAKE_128F, 32);
        encryptionAlgos.put(EncryptionAlgorithm.SLH_DSA_SHAKE_256S, 32);
        encryptionAlgos.put(EncryptionAlgorithm.SLH_DSA_SHAKE_256F, 32);
        encryptionAlgos.put(EncryptionAlgorithm.EDDSA, 32);
        encryptionAlgos.put(EncryptionAlgorithm.ECDSA, 256);

        return encryptionAlgos;
    }

    /**
     * This returns a list of supported digest algorithms for the certificate verifier.
     * Specifically, the digests supported within revocation data.
     * This is analogous to getAllowedEncryptionAlgorithms()
     * @return
     */
    public static Collection<DigestAlgorithm> getAllowedDigestAlgorithms()
    {
        Collection<DigestAlgorithm> allowedDigests = new ArrayList<>();
        allowedDigests.add(DigestAlgorithm.SHA256);
        allowedDigests.add(DigestAlgorithm.SHA512);
        allowedDigests.add(DigestAlgorithm.SHA3_256);
        allowedDigests.add(DigestAlgorithm.SHA3_512);
        allowedDigests.add(DigestAlgorithm.SHAKE256);
        allowedDigests.add(DigestAlgorithm.SHAKE128);

        return allowedDigests;
    }

    /**
     * This method checks if the following parameter combination is supported.
     * Currently, the method only verifies that in the case of sequential hybrid signing, the signature level is LTA.
     * This is because sequential hybrid signing, i.e., the application of an archival timestamp, makes sense only if the classical timestamp is already present.
     * @param mode Signing mode (classical, purely PQ, ...)
     * @param format AdES mode (XAdES, CAdES, ...)
     * @param level AdES signature level (B, T, LT, LTA)
     * @return
     */
    public static boolean areValidParams(SignerMode mode, SignatureFormat format, SignatureLevel level)
    {
        if (mode != SignerMode.SEQUENTIAL_HYBRID)
        {
            return true;
        }
        if (format == SignatureFormat.XAdES && level == SignatureLevel.XAdES_BASELINE_LTA)
        {
            return true;
        }
        if (format == SignatureFormat.CAdES && level == SignatureLevel.CAdES_BASELINE_LTA)
        {
            return true;
        }
        if (format == SignatureFormat.PAdES && level == SignatureLevel.PAdES_BASELINE_LTA)
        {
            return true;
        }
        if (format == SignatureFormat.JAdES && level == SignatureLevel.JAdES_BASELINE_LTA)
        {
            return true;
        }

        return false;
    }

    /**
     * Returns signature parameter class needed by the signature service.
     * Since none of the signature parameter classes share an appropriate ancestor (AbstractSignatureParameters is parametrized)
     * we need to create individual parameters for each format.
     * The parameters are currently set to always use enveloping signature packaging.
     * @param format AdES format
     * @param level AdES signature level
     * @param signatureAlgorithm Signature algorithm to be used
     * @param documentDigestAlgorithm Digest algorithm used to hash the signed document (different from the one used internally by the signature algorithm).
     * @param timestampImprintDigestAlgorithm Digest algorithm used to hash the AdES signature that is to be timestamped.
     * @return Parameters
     */
    public static AbstractSignatureParameters getSignatureParameters(SignatureFormat format, SignatureLevel level, SignatureAlgorithm signatureAlgorithm, DigestAlgorithm documentDigestAlgorithm, DigestAlgorithm timestampImprintDigestAlgorithm)
    {
        //setDigest is by default SHA-512 since default sig. alg. is RSA with SHA-512
        //setDigestAlgorithm vs setReferenceDigestAlgorithm behaviours:
        // In XAdES setReferenceDigestAlgorithm is the digest used to hash references (<ds:Reference>)
        // In XAdES if the reference digest is null, then it is copied from setDigestAlgorithm
        // setDigestAlgorithm decides the specific signature algorithm - ECDSA implied by pubkey, but internal hash decided based on this
        // In CAdES and PAdES setReferenceDigestAlgorithm does not do anything
        // In CAdES and PAdES setDigestAlgorithm decides the signature alg. as in XAdES
        // For detached CMS signatures, the message-digest parameter has to be the same as the internal signature hash.
        // Therefore, is not possible to hash the detached content with SHA-512, but then sign it with an algorithm that, e.g., uses SHA-256 internally.

        switch (format)
        {
            case XAdES ->
            {
                XAdESSignatureParameters parameters = new XAdESSignatureParameters();
                parameters.setSignatureLevel(level);
                parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
                parameters.setDigestAlgorithm(documentDigestAlgorithm);
                //parameters.setReferenceDigestAlgorithm(defaultDigestAlgorithm); //uncomment to use a different reference digest
                parameters.setManifestSignature(false);
                //timestamp imprint hashes
                parameters.getSignatureTimestampParameters().setDigestAlgorithm(timestampImprintDigestAlgorithm);
                parameters.getArchiveTimestampParameters().setDigestAlgorithm(timestampImprintDigestAlgorithm);
                return parameters;
            }
            case CAdES ->
            {
                CAdESSignatureParameters parameters = new CAdESSignatureParameters();
                parameters.setSignatureLevel(level);
                parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
                parameters.setDigestAlgorithm(documentDigestAlgorithm);
                //timestamp imprint hashes
                parameters.getSignatureTimestampParameters().setDigestAlgorithm(timestampImprintDigestAlgorithm);
                parameters.getArchiveTimestampParameters().setDigestAlgorithm(timestampImprintDigestAlgorithm);
                return parameters;
            }
            case PAdES ->
            {
                PAdESSignatureParameters parameters = new PAdESSignatureParameters();
                parameters.setSignatureLevel(level);
                parameters.setDigestAlgorithm(documentDigestAlgorithm);
                // set digest also influences the signing algorithm - for ecdsa, it selects version based on this
                // parameters.setDigestAlgorithm();
                // dont set digestAlgorithm as PDF is detached CMS where the digest is the message-digest parameter
                // but according to RFC that needs to be the "internal hash" of the signature so its determined by that
                // in CAdES the parameter is ignored and the internal hash is decided by BouncyCastle
                // see PAdESSignerInfoGeneratorBuilder + CMSSignerInfoGeneratorBuilder
                // in PAdES however the message-digest value is inserted separately from the SignerInfoGenerator
                // that fills in the digest algorithm OID based on the signature alg
                // so it becomes that the PAdES signature says digest used is SHAKE-256 but the value is actually computed using the alg set below
                // parameters.setDigestAlgorithm(defaultDigestAlgorithm);
                //timestamp imprint hashes
                parameters.getSignatureTimestampParameters().setDigestAlgorithm(timestampImprintDigestAlgorithm);
                parameters.getArchiveTimestampParameters().setDigestAlgorithm(timestampImprintDigestAlgorithm);

                int[] contentSizes = Utils.getPDFContentSizes(signatureAlgorithm);
                parameters.setContentSize(contentSizes[0]);
                parameters.getArchiveTimestampParameters().setContentSize(contentSizes[1]);
                return parameters;
            }
            case JAdES ->
            {
                JAdESSignatureParameters parameters = new JAdESSignatureParameters();
                parameters.setSignatureLevel(level);
                parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
                parameters.setDigestAlgorithm(documentDigestAlgorithm);
                parameters.setJwsSerializationType(JWSSerializationType.FLATTENED_JSON_SERIALIZATION);
                parameters.getSignatureTimestampParameters().setDigestAlgorithm(timestampImprintDigestAlgorithm);
                parameters.getArchiveTimestampParameters().setDigestAlgorithm(timestampImprintDigestAlgorithm);
//                parameters.getArchiveTimestampParameters().setCanonicalizationMethod(); //currently not supported so archival not working
                parameters.setBase64UrlEncodedEtsiUComponents(false);
                return parameters;
            }
            default ->
            {
                return null;
            }
        }
    }

}
