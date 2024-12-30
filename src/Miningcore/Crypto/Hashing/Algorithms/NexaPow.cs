using System.Diagnostics;
using System.Security.Cryptography;
using Miningcore.Configuration;
using Miningcore.Contracts;
using Miningcore.Extensions;
using Miningcore.Messaging;
using Miningcore.Notifications.Messages;
using NLog;

namespace Miningcore.Crypto.Hashing.Algorithms;

/// <summary>
/// NexaPow
/// </summary>
[Identifier("nexapow")]
public unsafe class NexaPow :
    IHashAlgorithm,
    IHashAlgorithmInit
{
    private IntPtr ctx = IntPtr.Zero;
    internal static IMessageBus messageBus;

    public void Digest(ReadOnlySpan<byte> data, Span<byte> result, params object[] extra)
    {
        Contract.Requires<ArgumentException>(result.Length >= 32);
        Contract.RequiresNonNull(ctx);

        var sw = Stopwatch.StartNew();
        int success;

        // Calculate miningHash which is the double_sha256(candidateHash || nonce)
        Span<byte> miningHash = stackalloc byte[32];
        var dsha = new Sha256D();
        dsha.Digest(data, miningHash);

        // Calculate h1, the sha256(miningHash)
        Span<byte> h1 = stackalloc byte[32];
        using(var hasher = SHA256.Create())
        {
            hasher.TryComputeHash(miningHash, h1, out _);
        }

        Span<byte> signature = stackalloc byte[64];
        fixed(byte* input = h1)
        {
            fixed(byte* output = signature)
            {
                // Use miningHash as a private key (POW fails if it is invalid)
                fixed(byte* key = miningHash)
                {
                    // Sign h1 resulting in sig
                    success = Native.NexaPow.schnorr_sign(ctx, input, output, key, (uint) h1.Length);
                }
            }
        }

        // powhash = sha256(sig)
        using(var hasher = SHA256.Create())
        {
            hasher.TryComputeHash(signature, result, out _);
        }

        if(success == 0)
        {
            Logger.Error(() => "Failed to sign hash");
        }

        messageBus?.SendTelemetry("NexaPow", TelemetryCategory.Hash, sw.Elapsed, success == 1);
    }

    private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();

    public bool DigestInit(PoolConfig poolConfig)
    {
        ctx = Native.NexaPow.schnorr_init();
        if(ctx == IntPtr.Zero)
        {
            Logger.Error(() => "Failed to initialize schnorr context");
            return false;
        }
        Logger.Info(() => "Initialized schnorr context");
        return true;
    }
}
