using System;
using System.Collections.Concurrent;
using System.Linq;
using Miningcore.Crypto;
using Contract = Miningcore.Contracts.Contract;

namespace Miningcore.Blockchain.Handshake;

public class HandshakeMerkleTree
{
    private readonly byte[] EMPTY = new byte[0];
    private readonly byte[] INTERNAL = { 0x01 };
    private readonly byte[] LEAF = { 0x00 };

    public List<byte[]> CreateTree(IHashAlgorithm hasher, List<byte[]> leaves)
    {
        Contract.RequiresNonNull(hasher);
        Contract.RequiresNonNull(leaves);

        var nodes = new List<byte[]>();
        var sentinel = HashEmpty(hasher);

        foreach (var data in leaves)
        {
            var leaf = HashLeaf(hasher, data);
            nodes.Add(leaf);
        }

        int size = nodes.Count;
        int i = 0;

        if (size == 0)
        {
            nodes.Add(sentinel);
            return nodes;
        }

        while (size > 1)
        {
            for (int j = 0; j < size; j += 2)
            {
                int l = j;
                int r = j + 1;
                var left = nodes[i + l];
                var right = (r < size) ? nodes[i + r] : sentinel;
                var hash = HashInternal(hasher, left, right);
                nodes.Add(hash);
            }

            i += size;
            size = (size + 1) >> 1;
        }

        return nodes;
    }

    public byte[] CreateRoot(IHashAlgorithm hasher, List<byte[]> leaves)
    {
        var nodes = CreateTree(hasher, leaves);
        return nodes.LastOrDefault();
    }

    public byte[] HashEmpty(IHashAlgorithm hasher)
    {
        Span<byte> resultBytes = stackalloc byte[32];
        hasher.Digest((Span<byte>) this.EMPTY, resultBytes);
        
        return resultBytes.ToArray();
    }

    public byte[] HashLeaf(IHashAlgorithm hasher, byte[] data)
    {
        Span<byte> leafDataBytes = stackalloc byte[this.LEAF.Length + data.Length];
        this.LEAF.CopyTo(leafDataBytes);
        data.CopyTo(leafDataBytes[this.LEAF.Length..]);
        
        Span<byte> resultBytes = stackalloc byte[32];
        hasher.Digest(leafDataBytes, resultBytes);
        
        return resultBytes.ToArray();
    }

    public byte[] HashInternal(IHashAlgorithm hasher, byte[] left, byte[] right)
    {
        Contract.RequiresNonNull(right);
        
        Span<byte> internalLeftRightBytes = stackalloc byte[this.INTERNAL.Length + left.Length + right.Length];
        this.INTERNAL.CopyTo(internalLeftRightBytes);
        left.CopyTo(internalLeftRightBytes[this.INTERNAL.Length..]);
        right.CopyTo(internalLeftRightBytes[(this.INTERNAL.Length + left.Length)..]);
        
        Span<byte> resultBytes = stackalloc byte[32];
        hasher.Digest(internalLeftRightBytes, resultBytes);
        
        return resultBytes.ToArray();
    }
}

public class HandshakeBech32Decoder
{
    private readonly uint checksum;

    private readonly int[] TABLE = new int[]
    {
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        15, -1, 10, 17, 21, 20, 26, 30,
         7,  5, -1, -1, -1, -1, -1, -1,
        -1, 29, -1, 24, 13, 25,  9,  8,
        23, -1, 18, 22, 31, 27, 19, -1,
         1,  0,  3, 16, 11, 28, 12, 14,
         6,  4,  2, -1, -1, -1, -1, -1,
        -1, 29, -1, 24, 13, 25,  9,  8,
        23, -1, 18, 22, 31, 27, 19, -1,
         1,  0,  3, 16, 11, 28, 12, 14,
         6,  4,  2, -1, -1, -1, -1, -1
    };

    public HandshakeBech32Decoder(uint checksum = 1)
    {
        if (checksum < 0)
            throw new ArgumentException("Checksum cannot be negative.");
        
        this.checksum = checksum;
    }

    private uint polymod(uint c)
    {
        uint b = c >> 25;

        return ((c & 0x1ffffff) << 5)
          ^ (0x3b6a57b2 & (uint)-(b >> 0 & 1))
          ^ (0x26508e6d & (uint)-(b >> 1 & 1))
          ^ (0x1ea119fa & (uint)-(b >> 2 & 1))
          ^ (0x3d4233dd & (uint)-(b >> 3 & 1))
          ^ (0x2a1462b3 & (uint)-(b >> 4 & 1));
    }

    private (string, byte[]) Deserialize(string str)
    {
        if (string.IsNullOrEmpty(str) || str.Length < 8 || str.Length > 90)
            throw new ArgumentException("Invalid bech32 string length.");

        bool lower = false;
        bool upper = false;
        int hlen = 0;

        for (int i = 0; i < str.Length; i++)
        {
            char ch = str[i];

            if (ch < 33 || ch > 126)
                throw new ArgumentException("Invalid bech32 character.");

            if (ch >= 97 && ch <= 122)
                lower = true;
            else if (ch >= 65 && ch <= 90)
                upper = true;
            else if (ch == 49)
                hlen = i;
        }

        if (hlen == 0)
            throw new ArgumentException("Invalid bech32 human-readable part.");

        int dlen = str.Length - (hlen + 1);

        if (dlen < 6)
            throw new ArgumentException("Invalid bech32 data length.");

        if (lower && upper)
            throw new ArgumentException("Invalid bech32 casing.");

        uint chk = 1;
        string hrp = "";

        for (int i = 0; i < hlen; i++)
        {
            char ch = str[i];

            if (ch >= 65 && ch <= 90)
                ch += (char)32;

            chk = polymod(chk) ^ (uint)(ch >> 5);

            hrp += ch;
        }

        chk = polymod(chk);

        for (int i = 0; i < hlen; i++)
            chk = polymod(chk) ^ (uint)(str[i] & 0x1f);

        byte[] data = new byte[dlen - 6];
        int j = 0;

        for (int i = hlen + 1; i < str.Length; i++)
        {
            int val = TABLE[str[i]];

            if (val == -1)
                throw new ArgumentException("Invalid bech32 character.");

            chk = polymod(chk) ^ (uint)val;

            if (i < str.Length - 6)
                data[j++] = (byte)val;
        }

        if (chk != this.checksum)
            throw new ArgumentException("Invalid bech32 checksum.");

        return (hrp, data.Take(j).ToArray());
    }

    private byte[] Convert(byte[] dst, int dstoff, int dstbits, byte[] src, int srcoff, int srcbits, bool pad)
    {
        Contract.RequiresNonNull(dst);
        Contract.RequiresNonNull(src);

        if (dstoff < 0 || dstbits < 1 || dstbits > 8 ||
            srcoff < 0 || srcbits < 1 || srcbits > 8 ||
            dst.Length - dstoff < (src.Length * srcbits + dstbits - 1) / dstbits)
            throw new ArgumentException();

        int mask = (1 << dstbits) - 1;

        int acc = 0;
        int bits = 0;
        int i = srcoff;
        int j = dstoff;

        for (; i < src.Length; i++)
        {
            acc = (acc << srcbits) | src[i];
            bits += srcbits;

            while (bits >= dstbits)
            {
                bits -= dstbits;
                dst[j++] = (byte)((acc >> bits) & mask);
            }
        }

        int left = dstbits - bits;

        if (pad)
        {
            if (bits != 0)
                dst[j++] = (byte)((acc << left) & mask);
        }
        else
        {
            if (((acc << left) & mask) != 0 || bits >= srcbits)
                throw new ArgumentException("Invalid bits.");
        }

        return dst.Take(j).ToArray();
    }

    public (string, int, byte[]) Decode(string addr)
    {
        (string hrp, byte[] data) = Deserialize(addr);

        if (data.Length == 0 || data.Length > 65)
            throw new ArgumentException("Invalid bech32 data length.");

        int version = data[0];

        if (version > 31)
            throw new ArgumentException("Invalid bech32 version.");

        byte[] output = data; // Works because dstbits > srcbits.
        byte[] hash = Convert(output, 0, 8, data, 1, 5, false);

        if (hash.Length < 2 || hash.Length > 40)
            throw new ArgumentException("Invalid bech32 data length.");

        return (hrp, version, hash);
    }
}