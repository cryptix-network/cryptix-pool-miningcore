namespace Miningcore.Blockchain.Equihash;

public class EquihashExtraNonceProvider : ExtraNonceProviderBase
{
    public EquihashExtraNonceProvider(string poolId, byte? clusterInstanceId) : base(poolId, 3, clusterInstanceId)
    {
    }
}

public class VeruscoinExtraNonceProvider : ExtraNonceProviderBase
{
    public VeruscoinExtraNonceProvider(string poolId, byte? clusterInstanceId) : base(poolId, 4, clusterInstanceId)
    {
    }
}
