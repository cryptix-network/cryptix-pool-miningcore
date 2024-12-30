namespace Miningcore.Blockchain.Warthog;

public class WarthogExtraNonceProvider : ExtraNonceProviderBase
{
    public WarthogExtraNonceProvider(string poolId, int size, byte? clusterInstanceId) : base(poolId, size, clusterInstanceId)
    {
    }
}