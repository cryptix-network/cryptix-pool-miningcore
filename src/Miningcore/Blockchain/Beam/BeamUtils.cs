using System;
using System.Numerics;

namespace Miningcore.Blockchain.Beam;

public static class BeamUtils
{
    public static double UnpackedDifficulty(long packedDifficulty)
    {
        uint leadingBit = 1 << 24;
        long order = packedDifficulty >> 24;
        double result = (leadingBit | (packedDifficulty & leadingBit - 1)) * Math.Pow(2, order - 24);
        return (double) Math.Abs(result);
    }

    public static long PackedDifficulty(double unpackedDifficulty)
    {
        long bits = 32 - BitOperations.LeadingZeroCount(Convert.ToUInt32(Math.Round(unpackedDifficulty, MidpointRounding.ToEven)));
        long correctedOrder = bits - 24 - 1;
        long mantissa = (long) (unpackedDifficulty * Math.Pow(2, -correctedOrder) - Math.Pow(2, 24));
        long order = 24 + correctedOrder;
        return (long) (mantissa | (order << 24));
    }
}