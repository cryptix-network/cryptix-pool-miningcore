using System.Security.Cryptography;
using Miningcore.Contracts;
using Miningcore.Native;

namespace Miningcore.Crypto.Hashing.Algorithms;

[Identifier("cshake128")]
public unsafe class CShake128 : IHashAlgorithm
{
    public byte[] dataName { get; protected set; } = null;
    public byte[] dataCustom { get; protected set; } = null;
    
    public CShake128(byte[] dataName = null, byte[] dataCustom = null)
    {
        this.dataName = dataName;
        this.dataCustom = dataCustom;
    }
    
    public void Digest(ReadOnlySpan<byte> data, Span<byte> result, params object[] extra)
    {
        Contract.Requires<ArgumentException>(result.Length >= 32);

        fixed (byte* input = data)
        {
            fixed (byte* output = result)
            {
                fixed (byte* name = this.dataName)
                {
                    var nameLength = (this.dataName == null) ? 0 : this.dataName.Length;
                    fixed (byte* custom = this.dataCustom)
                    {
                        var customLength = (this.dataCustom == null) ? 0 : this.dataCustom.Length;
                        Multihash.cshake128(input, (uint) data.Length, name, (uint) nameLength, custom, (uint) customLength, output, (uint) result.Length);
                    }
                }
            }
        }
    }
}
