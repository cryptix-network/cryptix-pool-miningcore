namespace Miningcore.Blockchain.Progpow;

public class FiroExtraNonceProvider : ExtraNonceProviderBase
{
    public FiroExtraNonceProvider(string poolId, byte? clusterInstanceId) : base(poolId, FiroConstants.ExtranoncePlaceHolderLength, clusterInstanceId)
    {
    }
}

public class RavencoinExtraNonceProvider : ExtraNonceProviderBase
{
    public RavencoinExtraNonceProvider(string poolId, byte? clusterInstanceId) : base(poolId, RavencoinConstants.ExtranoncePlaceHolderLength, clusterInstanceId)
    {
    }
}