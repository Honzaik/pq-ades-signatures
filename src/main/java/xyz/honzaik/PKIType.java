package xyz.honzaik;

public enum PKIType
{
    CLASSICAL(GlobalConstants.CLASSICAL_PKI_KEYSTORE_PREFIX, GlobalConstants.CLASSICAL_PKI_TRUST_ANCHOR, GlobalConstants.CLASSICAL_PKI_TSA),
    PURELY_PQ(GlobalConstants.PURELY_PQ_PKI_KEYSTORE_PREFIX, GlobalConstants.PURELY_PQ_PKI_TRUST_ANCHOR, GlobalConstants.PURELY_PQ_PKI_TSA),
    COMPOSITE_HYBRID(GlobalConstants.COMPOSITE_PKI_KEYSTORE_PREFIX, GlobalConstants.COMPOSITE_PKI_TRUST_ANCHOR, GlobalConstants.COMPOSITE_PKI_TSA),
    ;

    private final String keystorePrefix;
    private final String trustAnchorName;
    private final String tsaName;

    PKIType(String keystorePrefix, String trustAnchorName, String tsaName)
    {
        this.keystorePrefix = keystorePrefix;
        this.trustAnchorName = trustAnchorName;
        this.tsaName = tsaName;
    }

    public String getKeystorePrefix()
    {
        return keystorePrefix;
    }

    public String getTrustAnchorName()
    {
        return trustAnchorName;
    }

    public String getTsaName()
    {
        return tsaName;
    }
}
