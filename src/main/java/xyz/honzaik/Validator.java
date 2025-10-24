package xyz.honzaik;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.pki.jaxb.model.JAXBCertEntityRepository;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import jakarta.xml.bind.JAXB;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.Map;

/**
 * Class implementing a basic AdES validator for detached or embedded signatures.
 */
public class Validator
{
    private static final Logger LOG = LoggerFactory.getLogger(Validator.class);


    private Signer signer;
    private SignerMode validatorMode;

    public Validator(Map<PKIType, JAXBCertEntityRepository> pkis, SignerMode validatorMode) {
        this.validatorMode = validatorMode;
        this.signer = new Signer(pkis, this.validatorMode, null);
    }

    /**
     * Prints a validation report for signatures.
     * It supports embedded or detached signatures.
     * @param signatureFile File containing the signature.
     * @param documentFile File containing the signed document (without the signature). Null if signatureFileName is an embedded signature.
     * @throws IOException
     */
    public void validateSignature(File signatureFile, File documentFile) throws IOException
    {
        DSSDocument signatureToValidate = new FileDocument(signatureFile);

        CertificateVerifier verifier = signer.getCertificateVerifier();
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signatureToValidate);
        validator.setCertificateVerifier(verifier);
        if (documentFile != null) {
            DSSDocument detachedData = new FileDocument(documentFile);
            validator.setDetachedContents(Arrays.asList(detachedData));
        }
        Reports reports = validator.validateDocument(Utils.getFileFromResource("/" + GlobalConstants.POLICIES_FOLDER + "/" + GlobalConstants.POLICY_FILENAME));
        SimpleReport report = reports.getSimpleReport();
        ByteArrayOutputStream s = new ByteArrayOutputStream();
        JAXB.marshal(report.getJaxbModel(), s);
        LOG.info(s.toString());
    }

}
