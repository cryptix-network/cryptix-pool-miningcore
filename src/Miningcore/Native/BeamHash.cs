using System.Diagnostics;
using System.Runtime.InteropServices;
using Miningcore.Extensions;
using Miningcore.Messaging;
using Miningcore.Native;
using Miningcore.Notifications.Messages;

// ReSharper disable InconsistentNaming

namespace Miningcore.Native;

public unsafe class BeamHash
{
    /// <summary>
    /// Verify an BeamHash solution
    /// </summary>
    /// <param name="header">header (32 bytes)</param>
    /// <param name="header">nonce (8 bytes)</param>
    /// <param name="solution">beamhash solution without size-preamble</param>
    /// <param name="pow">beamhash pow</param>
    /// <returns>boolean</returns>
    [DllImport("libbeamhash", EntryPoint = "beamhash_verify_export", CallingConvention = CallingConvention.Cdecl)]
    public static extern bool beamhash_verify(byte* header, int header_length, byte* solution, int solution_length, byte* nonce, int nonce_length, int pow);
    
    private static int maxThreads = 1;

    public static int MaxThreads
    {
        get => maxThreads;
        set
        {
            if(sem.IsValueCreated)
                throw new InvalidOperationException("Too late: semaphore already created");

            maxThreads = value;
        }
    }

    internal static IMessageBus messageBus;

    protected static readonly Lazy<Semaphore> sem = new(() =>
        new Semaphore(maxThreads, maxThreads));

    /// <summary>
    /// Verify an BeamHash solution
    /// </summary>
    /// <param name="header">header (32 bytes)</param>
    /// <param name="header">nonce (8 bytes)</param>
    /// <param name="solution">beamhash solution without size-preamble</param>
    /// <param name="pow">beamhash pow</param>
    /// <returns>boolean</returns>
    public bool Verify(ReadOnlySpan<byte> header, ReadOnlySpan<byte> solution, ReadOnlySpan<byte> nonce, int pow)
    {
        var sw = Stopwatch.StartNew();

        try
        {
            sem.Value.WaitOne();

            fixed (byte* h = header)
            {
                fixed (byte* s = solution)
                {
                    fixed (byte* n = nonce)
                    {
                        var result = beamhash_verify(h, header.Length, s, solution.Length, n, nonce.Length, pow);

                        messageBus?.SendTelemetry("Beamhash-" + pow, TelemetryCategory.Hash, sw.Elapsed, result);

                        return result;
                    }
                }
            }
        }

        finally
        {
            sem.Value.Release();
        }
    }
}