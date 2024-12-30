namespace Miningcore.Blockchain.Kaspa;

public class KaspaExtraNonceProvider : ExtraNonceProviderBase
{
    public KaspaExtraNonceProvider(string poolId, int size, byte? clusterInstanceId) : base(poolId, size, clusterInstanceId)
    {
    }
}