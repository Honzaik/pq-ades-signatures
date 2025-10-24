package xyz.honzaik;

public abstract class GlobalConstants
{

    public static final String INPUT_FOLDER = "inputs";
    public static final String KEYSTORE_PASSWORD = "password";
    public static final String KEYSTORE_NAME = "tempKeyStore";
    public static final String POLICIES_FOLDER = "policy";
    public static final String POLICY_FILENAME = "ades-constraint.xml";
    public static final String PKI_DESCRIPTION_FOLDER = "pki";

    public static final String CLASSICAL_PKI_NAME = "ecdsa256";
    public static final String PURELY_PQ_PKI_NAME = "mldsa44";
    public static final String COMPOSITE_PKI_NAME = "mldsa44ecdsa256";

    public static final String CLASSICAL_PKI_KEYSTORE_PREFIX = "classical";
    public static final String PURELY_PQ_PKI_KEYSTORE_PREFIX = "purelyPQ";
    public static final String COMPOSITE_PKI_KEYSTORE_PREFIX = "compositePQ";

    public static final String CLASSICAL_PKI_TRUST_ANCHOR = "Classical Root Authority";
    public static final String PURELY_PQ_PKI_TRUST_ANCHOR = "Purely PQ Root Authority";
    public static final String COMPOSITE_PKI_TRUST_ANCHOR = "Composite PQ Root Authority";

    public static final String CLASSICAL_PKI_TSA = "Classical TSA";
    public static final String PURELY_PQ_PKI_TSA = "Purely PQ TSA";
    public static final String COMPOSITE_PKI_TSA = "Composite PQ TSA";

}
