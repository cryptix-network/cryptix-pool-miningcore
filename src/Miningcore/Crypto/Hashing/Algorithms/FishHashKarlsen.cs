using System;
using Miningcore.Contracts;
using Miningcore.Native;
using Miningcore.Time;
using NLog;

namespace Miningcore.Crypto.Hashing.Algorithms;

[Identifier("fishhashkarlsen")]
public unsafe class FishHashKarlsen : IHashAlgorithm
{
    private static readonly ILogger logger = LogManager.GetCurrentClassLogger();

    public byte fishHashKernel { get; private set; } = 1;
    private IntPtr handle = IntPtr.Zero;
    private readonly object genLock = new();

    public FishHashKarlsen(byte fishHashKernel = 1, bool fullContext = false, uint threads = 4)
    {
        Contract.Requires<ArgumentException>(fishHashKernel >= 1);

        this.fishHashKernel = fishHashKernel;

        var started = DateTime.Now;
        logger.Debug(() => $"Generating light cache");

        lock(genLock)
        {
            this.handle = Multihash.fishhashGetContext(fullContext);
            if(fullContext)
                Multihash.fishhashPrebuildDataset(this.handle, threads);
        }

        logger.Debug(() => $"Done generating light cache after {DateTime.Now - started}");
    }

    public void Digest(ReadOnlySpan<byte> data, Span<byte> result, params object[] extra)
    {
        Contract.Requires<ArgumentException>(this.handle != IntPtr.Zero);
        Contract.Requires<ArgumentException>(result.Length >= 32);

        fixed(byte* input = data)
        {
            fixed (byte* output = result)
            {
                Multihash.fishhaskarlsen(output, this.handle, input, (uint) data.Length, this.fishHashKernel);
            }
        }
    }
}
