package xyz.honzaik;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.TimestampParameters;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pki.jaxb.model.JAXBCertEntity;
import eu.europa.esig.dss.pki.jaxb.model.JAXBCertEntityRepository;
import eu.europa.esig.dss.pki.x509.revocation.crl.PKICRLSource;
import eu.europa.esig.dss.pki.x509.revocation.ocsp.PKIOCSPSource;
import eu.europa.esig.dss.pki.x509.tsp.PKITSPSource;
import eu.europa.esig.dss.signature.AbstractSignatureParameters;
import eu.europa.esig.dss.signature.AbstractSignatureService;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.validation.RevocationDataVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.CompositeRevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Class which implements AdES signing for all formats, levels and supports classical, purely and hybrid post-quantum signings.
 */

public class Signer
{
    private static final Logger LOG = LoggerFactory.getLogger(Signer.class);

    // classical, purely post-quantum, composite hybrid, sequential hybrid
    private final SignerMode mode;

    private KeyStore keyStore;
    private File keyStoreFile;
    private String signerSubjectName;

    private DigestAlgorithm defaultDigestAlgorithm;
    private DigestAlgorithm pqArchiveTimestampSignatureDigestAlgorithm;
    private DigestAlgorithm timestampMessageImprintDigestAlgorithm = DigestAlgorithm.SHA3_512;

    private DSSPrivateKeyEntry signingKeyEntry;
    private Pkcs12SignatureToken signingToken;
    private SignatureAlgorithm primarySignatureAlgorithm;
    private SignatureAlgorithm secondarySignatureAlgorithm;

    private CertificateVerifier certificateVerifier;
    private TSPSource primaryTSPSource;
    private TSPSource secondaryTSPSource;

    private final Map<PKIType, JAXBCertEntityRepository> pkis;

    public Signer(Map<PKIType, JAXBCertEntityRepository> pkis, SignerMode mode, String signerSubjectName)
    {
        this.pkis = pkis;
        this.mode = mode;
        this.signerSubjectName = signerSubjectName;

        if (signerSubjectName != null)
        { //if null, then we reuse this for validation and we do not need keystore init
            initKeyStore();
            initSigningKey();
        }

        //in the case of parallel PKI, primary is the classical PKI, secondary is the PQ PKI
        PKIType primaryPKIType = null;
        PKIType secondaryPKIType = null;

        switch (mode)
        {
            case CLASSICAL -> primaryPKIType = PKIType.CLASSICAL;
            case PURELY_PQ -> primaryPKIType = PKIType.PURELY_PQ;
            case COMPOSITE_HYBRID -> primaryPKIType = PKIType.COMPOSITE_HYBRID;
            case SEQUENTIAL_HYBRID ->
            {
                primaryPKIType = PKIType.CLASSICAL;
                secondaryPKIType = PKIType.PURELY_PQ;
            }
        }

        //digest algorithm used for CRL, OCSP etc. make sure it matches with the one paired with the signature in DSS
        defaultDigestAlgorithm = pkis.get(primaryPKIType).getAll().get(0).getCertificateToken().getSignatureAlgorithm().getDigestAlgorithm();
        if (secondaryPKIType != null)
        {
            pqArchiveTimestampSignatureDigestAlgorithm = pkis.get(secondaryPKIType).getAll().get(0).getCertificateToken().getSignatureAlgorithm().getDigestAlgorithm();
        }

        if (defaultDigestAlgorithm == null)
        {
            defaultDigestAlgorithm = DigestAlgorithm.SHA256;
        }

        certificateVerifier = getCertificateVerifier();
        primaryTSPSource = getPrimaryTSPSource();
        secondaryTSPSource = getSecondaryTSPSource();

    }

    public SignatureAlgorithm getPrimarySignatureAlgorithm()
    {
        return primarySignatureAlgorithm;
    }

    public SignatureAlgorithm getSecondarySignatureAlgorithm()
    {
        return secondarySignatureAlgorithm;
    }

    public SignerMode getMode()
    {
        return mode;
    }

    /**
     * Create a signing token from the loaded keystore. Specify signing key(s) and corresponding signing algorithms.
     */
    private void initSigningKey()
    {
        try
        {
            signingToken = new Pkcs12SignatureToken(keyStoreFile, new KeyStore.PasswordProtection(GlobalConstants.KEYSTORE_PASSWORD.toCharArray()));
        }
        catch (IOException e)
        {
            throw new RuntimeException(e);
        }

        switch (mode)
        {
            case CLASSICAL, SEQUENTIAL_HYBRID ->
                    signingKeyEntry = signingToken.getKey(PKIType.CLASSICAL.getKeystorePrefix() + "signingCert");
            case PURELY_PQ ->
                    signingKeyEntry = signingToken.getKey(PKIType.PURELY_PQ.getKeystorePrefix() + "signingCert");
            case COMPOSITE_HYBRID ->
                    signingKeyEntry = signingToken.getKey(PKIType.COMPOSITE_HYBRID.getKeystorePrefix() + "signingCert");
        }

        primarySignatureAlgorithm = signingKeyEntry.getCertificate().getSignatureAlgorithm();
        if (mode == SignerMode.SEQUENTIAL_HYBRID)
        {
            secondarySignatureAlgorithm = pkis.get(PKIType.PURELY_PQ).getCertEntityBySubject(PKIType.PURELY_PQ.getTsaName()).getCertificateToken().getSignatureAlgorithm();
        }
    }

    /**
     * Creates a temporary PKCS12 keystore filled with keys and certs from the PKI
     */
    private void initKeyStore()
    {
        try
        {
            this.keyStoreFile = Files.createTempFile(GlobalConstants.KEYSTORE_NAME, ".p12").toFile();
            this.keyStore = KeyStore.getInstance("PKCS12");
            this.keyStore.load(null);
            this.keyStore.store(new FileOutputStream(this.keyStoreFile), GlobalConstants.KEYSTORE_PASSWORD.toCharArray());

            //extract keys from JAXB and put them into a keystore, so we can create Pkcs12SignatureToken
            for (Map.Entry<PKIType, JAXBCertEntityRepository> pki : pkis.entrySet())
            {
                JAXBCertEntity signerEntity = pki.getValue().getCertEntityBySubject(signerSubjectName);
                List<Certificate> chainList = new ArrayList<>();
                for (CertificateToken certificateToken : signerEntity.getCertificateChain())
                {
                    chainList.add(certificateToken.getCertificate());
                }

                this.keyStore.setKeyEntry(pki.getKey().getKeystorePrefix() + "signingCert", signerEntity.getPrivateKey(), GlobalConstants.KEYSTORE_PASSWORD.toCharArray(), chainList.toArray(new Certificate[0]));
                this.keyStore.store(new FileOutputStream(keyStoreFile), GlobalConstants.KEYSTORE_PASSWORD.toCharArray());

                LOG.info("loaded " + pki.getKey().getKeystorePrefix() + " key into keystore for subject " + signerSubjectName);
            }
        }
        catch (KeyStoreException | IOException | CertificateException | NoSuchAlgorithmException e)
        {
            throw new RuntimeException(e);
        }
    }

    /**
     * Set up trust anchors.
     * @return trust anchor list
     */
    private CommonTrustedCertificateSource getTrustedList()
    {
        CommonTrustedCertificateSource trustedList = new CommonTrustedCertificateSource();
        switch (this.mode)
        {
            case CLASSICAL ->
                    trustedList.addCertificate(pkis.get(PKIType.CLASSICAL).getCertEntityBySubject(PKIType.CLASSICAL.getTrustAnchorName()).getCertificateToken());
            case PURELY_PQ ->
                    trustedList.addCertificate(pkis.get(PKIType.PURELY_PQ).getCertEntityBySubject(PKIType.PURELY_PQ.getTrustAnchorName()).getCertificateToken());
            case COMPOSITE_HYBRID ->
                    trustedList.addCertificate(pkis.get(PKIType.COMPOSITE_HYBRID).getCertEntityBySubject(PKIType.COMPOSITE_HYBRID.getTrustAnchorName()).getCertificateToken());
            case SEQUENTIAL_HYBRID ->
            {
                trustedList.addCertificate(pkis.get(PKIType.CLASSICAL).getCertEntityBySubject(PKIType.CLASSICAL.getTrustAnchorName()).getCertificateToken());
                trustedList.addCertificate(pkis.get(PKIType.PURELY_PQ).getCertEntityBySubject(PKIType.PURELY_PQ.getTrustAnchorName()).getCertificateToken());
            }
        }

        return trustedList;
    }

    /**
     * Creates an array of revocation sources.
     * At index 0 the source is an OCSP responder.
     * At inder 1 the source is a CRL.
     * For sequential hybrids, the returned source is a CompositeRevocationSource containing classical and PQ sources.
     * @return An array of revocation sources.
     */
    private RevocationSource[] getRevocationSources()
    {
        RevocationSource[] revocationSources = new RevocationSource[2];

        switch (this.mode)
        {
            case CLASSICAL ->
            {
                revocationSources[0] = new PKIOCSPSource(pkis.get(PKIType.CLASSICAL));
                revocationSources[1] = new PKICRLSource(pkis.get(PKIType.CLASSICAL));
            }
            case PURELY_PQ ->
            {
                PKIOCSPSource pqOCSPSource = new PKIOCSPSource(pkis.get(PKIType.PURELY_PQ));
                PKICRLSource pqCRLSource = new PKICRLSource(pkis.get(PKIType.PURELY_PQ));
                //we need to set it explicitly because, by default, sources use SHA512 and library will not find PQ signature with SHA512 in the database since there exists a specific set of pairings (signature algorithm, hash function)
                pqOCSPSource.setDigestAlgorithm(defaultDigestAlgorithm);
                pqCRLSource.setDigestAlgorithm(defaultDigestAlgorithm);

                revocationSources[0] = pqOCSPSource;
                revocationSources[1] = pqCRLSource;

            }
            case COMPOSITE_HYBRID ->
            {
                PKIOCSPSource pqOCSPSource = new PKIOCSPSource(pkis.get(PKIType.COMPOSITE_HYBRID));
                PKICRLSource pqCRLSource = new PKICRLSource(pkis.get(PKIType.COMPOSITE_HYBRID));
                //we need to set it explicitly because, by default, sources use SHA512 and library will not find PQ signature with SHA512 in the database since there exists a specific set of pairings (signature algorithm, hash function)
                pqOCSPSource.setDigestAlgorithm(defaultDigestAlgorithm);
                pqCRLSource.setDigestAlgorithm(defaultDigestAlgorithm);

                revocationSources[0] = pqOCSPSource;
                revocationSources[1] = pqCRLSource;
            }
            case SEQUENTIAL_HYBRID ->
            {
                PKIOCSPSource classicalOCSPSource = new PKIOCSPSource(pkis.get(PKIType.CLASSICAL));
                PKIOCSPSource pqOCSPSource = new PKIOCSPSource(pkis.get(PKIType.PURELY_PQ));
                PKICRLSource classicalCRLSource = new PKICRLSource(pkis.get(PKIType.CLASSICAL));
                PKICRLSource pqCRLSource = new PKICRLSource(pkis.get(PKIType.PURELY_PQ));

                //for classical, we let the default (SHA-512), but for PQ use the one matching the PQ alg
                pqOCSPSource.setDigestAlgorithm(pqArchiveTimestampSignatureDigestAlgorithm);
                pqCRLSource.setDigestAlgorithm(pqArchiveTimestampSignatureDigestAlgorithm);

                HashMap<String, RevocationSource> ocsps = new HashMap<>();
                HashMap<String, RevocationSource> crls = new HashMap<>();

                ocsps.put(PKIType.CLASSICAL.getKeystorePrefix(), classicalOCSPSource);
                ocsps.put(PKIType.PURELY_PQ.getKeystorePrefix(), pqOCSPSource);

                crls.put(PKIType.CLASSICAL.getKeystorePrefix(), classicalCRLSource);
                crls.put(PKIType.PURELY_PQ.getKeystorePrefix(), pqCRLSource);

                CompositeRevocationSource compositeOCSP = new CompositeRevocationSource();
                compositeOCSP.setSources(ocsps);

                CompositeRevocationSource compositeCRL = new CompositeRevocationSource();
                compositeCRL.setSources(crls);

                revocationSources[0] = compositeOCSP;
                revocationSources[1] = compositeCRL;
            }
        }

        return revocationSources;
    }

    /**
     * Create certificate verifier that is used during signature creation.
     * @return A certificate verifier.
     */
    public CertificateVerifier getCertificateVerifier()
    {
        CertificateVerifier certificateVerifier = new CommonCertificateVerifier();

        certificateVerifier.setTrustedCertSources(getTrustedList());
        RevocationSource[] revocationSources = getRevocationSources();

        certificateVerifier.setOcspSource(revocationSources[0]);
        certificateVerifier.setCrlSource(revocationSources[1]);

        RevocationDataVerifier revocationDataVerifier = RevocationDataVerifier.createDefaultRevocationDataVerifier();
        revocationDataVerifier.setAcceptableEncryptionAlgorithmKeyLength(Utils.getAllowedEncryptionAlgorithms());
        revocationDataVerifier.setAcceptableDigestAlgorithms(Utils.getAllowedDigestAlgorithms());

        certificateVerifier.setRevocationDataVerifier(revocationDataVerifier);

        return certificateVerifier;
    }

    /**
     * Creates the signature for the input file.
     * @param inputFileBytes File to be signed in bytes.
     * @param format AdES format - XAdES, PAdES, CAdES, or JAdES. Must be compatible with the input file. E.g., only PDF can be signed with PAdES.
     * @param level Signature level - B, T, LT, LTA.
     * @return The signed file.
     */
    public byte[] signFileBytes(byte[] inputFileBytes, SignatureFormat format, SignatureLevel level)
    {
        if (!Utils.areValidParams(mode, format, level))
        {
            throw new IllegalArgumentException("Sequential hybrid can be only used for LTA level");
        }

        AbstractSignatureService service = Utils.getSignatureService(format, certificateVerifier);
        AbstractSignatureParameters parameters = Utils.getSignatureParameters(format, level, primarySignatureAlgorithm, defaultDigestAlgorithm, timestampMessageImprintDigestAlgorithm);

        DSSDocument dataToBeSigned = new InMemoryDocument(inputFileBytes);
        parameters.setSigningCertificate(signingKeyEntry.getCertificate());
        parameters.setCertificateChain(signingKeyEntry.getCertificateChain());

        service.setTspSource(primaryTSPSource);
        ToBeSigned tbs = service.getDataToSign(dataToBeSigned, parameters);

        SignatureValue signatureValue = signingToken.sign(tbs, parameters.getDigestAlgorithm(), signingKeyEntry);

        DSSDocument signedDocument = service.signDocument(dataToBeSigned, parameters, signatureValue);

        //in the case we are signing in a sequential hybrid mode, add a purely PQ archival timestamp at the end
        if (mode == SignerMode.SEQUENTIAL_HYBRID)
        {
            signedDocument = applyPQArchivalTimestamp(format, level, signedDocument);
        }

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        try
        {
            signedDocument.writeTo(outputStream);
        }
        catch (IOException e)
        {
            throw new RuntimeException(e);
        }

        return outputStream.toByteArray();
    }

    /**
     * Augments an existing AdES LTA signature with an additional purely post-quantum archival timestamp.
     * @param format AdES format - XAdES, PAdES, CAdES, or JAdES. Must be compatible with the input file. E.g., only PDF can be signed with PAdES.
     * @param level Signature level - B, T, LT, LTA.
     * @param signedDocument Document to be additionally timestamped.
     * @return
     */
    private DSSDocument applyPQArchivalTimestamp(SignatureFormat format, SignatureLevel level, DSSDocument signedDocument)
    {
        AbstractSignatureParameters parameters = Utils.getSignatureParameters(format, level, secondarySignatureAlgorithm, defaultDigestAlgorithm, timestampMessageImprintDigestAlgorithm);
        TimestampParameters archiveTimestampParameters = (TimestampParameters) parameters.getArchiveTimestampParameters();
        archiveTimestampParameters.setDigestAlgorithm(timestampMessageImprintDigestAlgorithm); //message imprint digest algorithm setting, the signature digest algorithm is decided by the TSPSource
        AbstractSignatureService service = Utils.getSignatureService(format, certificateVerifier);

        service.setTspSource(secondaryTSPSource);

        return service.extendDocument(signedDocument, parameters);
    }

    /**
     * Returns a timestamping source based on the PKI mode.
     * For sequential hybrid, the primary source is classical and the secondary one is returned by getSecondaryTSPSource().
     * @return Timestamping source
     */
    private PKITSPSource getPrimaryTSPSource()
    {
        PKITSPSource source = null;
        switch (mode)
        {
            case CLASSICAL, SEQUENTIAL_HYBRID ->
                    source = new PKITSPSource(pkis.get(PKIType.CLASSICAL).getCertEntityBySubject(PKIType.CLASSICAL.getTsaName()));
            case PURELY_PQ ->
                    source = new PKITSPSource(pkis.get(PKIType.PURELY_PQ).getCertEntityBySubject(PKIType.PURELY_PQ.getTsaName()));
            case COMPOSITE_HYBRID ->
                    source = new PKITSPSource(pkis.get(PKIType.COMPOSITE_HYBRID).getCertEntityBySubject(PKIType.COMPOSITE_HYBRID.getTsaName()));
        }

        source.setTsaPolicy("1.2.3.4.5.66");
        //this digest is used during signing, it must be paired/supported with the signature algorithm.
        source.setDigestAlgorithm(defaultDigestAlgorithm);
        //this digest is used to create the message imprint
        source.setAcceptedDigestAlgorithms(Arrays.asList(timestampMessageImprintDigestAlgorithm));
        return source;
    }

    /**
     * Returns a secondary PQ timestamping source.
     * Only supported if the PKI is hybrid parallel (sequential hybrid signing).
     * @return Secondary PQ timestamping source
     */
    private PKITSPSource getSecondaryTSPSource()
    {
        if (mode != SignerMode.SEQUENTIAL_HYBRID)
        {
            return null;
        }
        PKITSPSource source = new PKITSPSource(pkis.get(PKIType.PURELY_PQ).getCertEntityBySubject(PKIType.PURELY_PQ.getTsaName()));
        source.setTsaPolicy("1.2.3.4.5.67"); //we use a different dummy policy to differentiate between the two archival timestamps.
        source.setDigestAlgorithm(pqArchiveTimestampSignatureDigestAlgorithm);
        source.setAcceptedDigestAlgorithms(Arrays.asList(timestampMessageImprintDigestAlgorithm));

        return source;
    }

}