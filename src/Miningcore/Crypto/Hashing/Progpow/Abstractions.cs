using NLog;

namespace Miningcore.Crypto.Hashing.Progpow;

public interface IProgpowLight : IDisposable
{
    void Setup(int totalCache, ulong hardForkBlock = 0);
    Task<IProgpowCache> GetCacheAsync(ILogger logger, int block, CancellationToken ct);
    string AlgoName { get; }
}

public interface IProgpowCache : IDisposable
{
    public byte[] SeedHash { get; set; }
    bool Compute(ILogger logger, int blockNumber, byte[] hash, ulong nonce, out byte[] mixDigest, out byte[] result);
}