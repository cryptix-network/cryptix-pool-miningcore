using System.Runtime.InteropServices;
using Miningcore.Blockchain.Equihash;
using Miningcore.Contracts;
using Miningcore.Native;

// ReSharper disable InconsistentNaming

namespace Miningcore.Native;

public unsafe class Verushash
{
    [DllImport("libverushash", EntryPoint = "verushash2b2_export", CallingConvention = CallingConvention.Cdecl)]
    public static extern void verushash2b2(byte* input, byte* output, int input_length);

    [DllImport("libverushash", EntryPoint = "verushash2b2o_export", CallingConvention = CallingConvention.Cdecl)]
    public static extern void verushash2b2o(byte* input, byte* output, int input_length);
    
    [DllImport("libverushash", EntryPoint = "verushash2b1_export", CallingConvention = CallingConvention.Cdecl)]
    public static extern void verushash2b1(byte* input, byte* output, int input_length);
    
    [DllImport("libverushash", EntryPoint = "verushash2b_export", CallingConvention = CallingConvention.Cdecl)]
    public static extern void verushash2b(byte* input, byte* output, int input_length);
    
    [DllImport("libverushash", EntryPoint = "verushash2_export", CallingConvention = CallingConvention.Cdecl)]
    public static extern void verushash2(byte* input, byte* output, int input_length);
    
    [DllImport("libverushash", EntryPoint = "verushash_export", CallingConvention = CallingConvention.Cdecl)]
    public static extern void verushash(byte* input, byte* output, int input_length);
    
    public void Digest(ReadOnlySpan<byte> data, Span<byte> result, string version = null, params object[] extra)
    {
        Contract.Requires<ArgumentException>(result.Length >= 32);

        fixed (byte* input = data)
        {
            fixed (byte* output = result)
            {
                switch(version)
                {
                    case VeruscoinConstants.HashVersion2b2:
                        verushash2b2(input, output, data.Length);
                        break;

                    case VeruscoinConstants.HashVersion2b2o:
                        verushash2b2o(input, output, data.Length);
                        break;

                    case VeruscoinConstants.HashVersion2b1:
                        verushash2b1(input, output, data.Length);
                        break;

                    case VeruscoinConstants.HashVersion2b:
                        verushash2b(input, output, data.Length);
                        break;

                    case VeruscoinConstants.HashVersion2:
                        verushash2(input, output, data.Length);
                        break;

                    default:
                        verushash(input, output, data.Length);
                        break;
                }
            }
        }
    }
}