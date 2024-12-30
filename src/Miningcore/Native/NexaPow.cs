using System.Runtime.InteropServices;

namespace Miningcore.Native;

public static unsafe class NexaPow
{
    [DllImport("libnexapow", EntryPoint = "schnorr_init_export", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr schnorr_init();

    [DllImport("libnexapow", EntryPoint = "schnorr_sign_export", CallingConvention = CallingConvention.Cdecl)]
    public static extern int schnorr_sign(IntPtr ctx, byte* input, void* output, byte* key, uint inputLength);
}
