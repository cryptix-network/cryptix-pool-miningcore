using System.Diagnostics;
using Miningcore.Blockchain.Progpow;
using Miningcore.Contracts;
using Miningcore.Extensions;
using Miningcore.Messaging;
using Miningcore.Native;
using Miningcore.Notifications.Messages;
using NLog;

namespace Miningcore.Crypto.Hashing.Progpow.Kawpow;

[Identifier("kawpow")]
public class Cache : IProgpowCache
{
    public Cache(int epoch)
    {
        Epoch = epoch;
        LastUsed = DateTime.Now;
    }

    private IntPtr handle = IntPtr.Zero;
    private bool isGenerated = false;
    private readonly object genLock = new();
    internal static IMessageBus messageBus;
    public int Epoch { get; }
    public byte[] SeedHash { get; set; }
    public DateTime LastUsed { get; set; }

    public void Dispose()
    {
        if(handle != IntPtr.Zero)
        {
            KawPow.DestroyContext(handle);
            handle = IntPtr.Zero;
        }
    }

    public async Task GenerateAsync(ILogger logger, CancellationToken ct)
    {
        if(handle == IntPtr.Zero)
        {
            await Task.Run(() =>
            {
                lock(genLock)
                {
                    if(!isGenerated)
                    {
                        // re-check after obtaining lock
                        if(handle != IntPtr.Zero)
                            return;

                        var started = DateTime.Now;
                        logger.Debug(() => $"Generating cache for epoch {Epoch}");

                        handle = KawPow.CreateContext(Epoch);

                        logger.Debug(() => $"Done generating cache for epoch {Epoch} after {DateTime.Now - started}");

                        // get the seed hash for this epoch
                        var res = KawPow.calculate_epoch_seed(Epoch);
                        SeedHash = res.bytes;
                        logger.Info(() => $"Seed hash for epoch {Epoch} is {SeedHash.ToHexString()}");
                        
                        isGenerated = true;
                    }
                }
            }, ct);
        }
    }

    public unsafe bool Compute(ILogger logger, int blockNumber, byte[] hash, ulong nonce, out byte[] mixDigest, out byte[] result)
    {
        Contract.RequiresNonNull(hash);

        var sw = Stopwatch.StartNew();

        mixDigest = null;
        result = null;

        var value = new KawPow.Ethash_result();

        var inputHash = new KawPow.Ethash_hash256();
        inputHash.bytes = hash;

        fixed(byte* input = hash)
        {
            value = KawPow.hash(handle, blockNumber, ref inputHash, nonce);
        }

        if(value.final_hash.bytes == null)
        {
            logger.Error(() => $"KawPow.hash returned null");
            return false;
        }

        mixDigest = value.mix_hash.bytes;
        result = value.final_hash.bytes;

        messageBus?.SendTelemetry("Kawpow", TelemetryCategory.Hash, sw.Elapsed, true);

        return true;
    }
}