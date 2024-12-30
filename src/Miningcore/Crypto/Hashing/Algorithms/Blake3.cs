using Miningcore.Contracts;
using Miningcore.Native;

namespace Miningcore.Crypto.Hashing.Algorithms;

[Identifier("blake3")]
public unsafe class Blake3 : IHashAlgorithm
{
    public byte[] dataKey { get; protected set; } = null;
    
    public Blake3(byte[] dataKey = null)
    {
        this.dataKey = dataKey;
    }

    public void Digest(ReadOnlySpan<byte> data, Span<byte> result, params object[] extra)
    {
        Contract.Requires<ArgumentException>(result.Length >= 32);

        fixed (byte* input = data)
        {
            fixed (byte* output = result)
            {
                fixed (byte* key = this.dataKey)
                {
                    var keyLength = (this.dataKey == null) ? 0 : this.dataKey.Length;
                    Multihash.blake3(input, output, (uint) data.Length, key, (uint) keyLength);
                }
            }
        }
    }
}
