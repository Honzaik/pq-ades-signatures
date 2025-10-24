package xyz.honzaik;

import eu.europa.esig.dss.pki.jaxb.JAXBPKILoader;
import eu.europa.esig.dss.pki.jaxb.model.JAXBCertEntityRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class PKILoader
{
    private static final Logger LOG = LoggerFactory.getLogger(PKILoader.class);

    private static Map<String, JAXBCertEntityRepository> loadedPKIs = new HashMap<>();

    private PKILoader(){}

    private static void loadPKI(String name) throws IOException
    {
        JAXBPKILoader loader = new JAXBPKILoader();
        JAXBCertEntityRepository jaxbCertEntityRepository = new JAXBCertEntityRepository();
        File pkiDescriptionFile = Utils.getFileFromResource("/" + GlobalConstants.PKI_DESCRIPTION_FOLDER + "/" + name + ".xml");
        loader.persistPKI(jaxbCertEntityRepository, pkiDescriptionFile);
        loadedPKIs.put(name, jaxbCertEntityRepository);
        LOG.info("Loaded PKI : {}", name);
    }

    public static JAXBCertEntityRepository getPKI(String name) throws IOException
    {
        if (!loadedPKIs.containsKey(name)) {
            loadPKI(name);
        }
        return loadedPKIs.get(name);
    }
}
