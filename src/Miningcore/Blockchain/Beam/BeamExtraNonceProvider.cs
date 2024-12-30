namespace Miningcore.Blockchain.Beam;

public class BeamExtraNonceProvider : ExtraNonceProviderBase
{
    public BeamExtraNonceProvider(string poolId, byte? clusterInstanceId) : base(poolId, 3, clusterInstanceId)
    {
    }
}