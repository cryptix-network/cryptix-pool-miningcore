using System;
using System.Globalization;
using System.Linq;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Text;
using Miningcore.Extensions;
using Miningcore.Util;

#pragma warning disable 3021 // disable CLSCompliant attribute warnings - http://msdn.microsoft.com/en-us/library/1x9049cy(v=vs.90).aspx

namespace Miningcore.Blockchain.Warthog;

public static class WarthogUtils
{
    // Bit-mask used for extracting the exponent bits of a Double (0x7ff0000000000000).
    public const long DBL_EXP_MASK = 0x7ff0000000000000L;

    // The number of bits in the mantissa of a Double, excludes the implicit leading 1 bit (52).
    public const int DBL_MANT_BITS = 52;

    // Bit-mask used for extracting the sign bit of a Double (0x8000000000000000).
    public const long DBL_SGN_MASK = -1 - 0x7fffffffffffffffL;

    // Bit-mask used for extracting the mantissa bits of a Double (0x000fffffffffffff).
    public const long DBL_MANT_MASK = 0x000fffffffffffffL;

    // Bit-mask used for clearing the exponent bits of a Double (0x800fffffffffffff).
    public const long DBL_EXP_CLR_MASK = DBL_SGN_MASK | DBL_MANT_MASK;

    public static double CalculateHashrate(WarthogCustomFloat sha256t, WarthogCustomFloat verus)
    {
        double hashrate = (10.0 / 3.0) * (double)sha256t * (Math.Pow(((double)WarthogConstants.ProofOfBalancedWorkC + (double)verus / (double)sha256t), 3.0) - Math.Pow((double)WarthogConstants.ProofOfBalancedWorkC, 3.0));

        return hashrate;
    }

    /* public static void Frexp(double value, out double significand, out int exponent)
    {
        // Special case for zero
        if(value == 0.0)
        {
            significand = 0.0;
            exponent = 0;
            return;
        }

        // Get the raw bits of the double
        long bits = BitConverter.DoubleToInt64Bits(value);

        bool negative = (bits >> 63) != 0;
        
        // Extract the exponent (bits 52-62)
        int rawExponent = (int)((bits >> 52) & 0x7FFL);
        
        // Extract the mantissa (bits 0-51)
        long mantissa = bits & 0xFFFFFFFFFFFFFL;

        // If the exponent is zero, this is a subnormal number
        if(rawExponent == 0)
            rawExponent++;
        // Add the implicit leading 1 bit to the mantissa
        else
            mantissa = mantissa | (1L << 52);
        
        // Adjust the exponent from the biased representation
        exponent = rawExponent - 1023;

        // Calculate the significand
        significand = mantissa / Math.Pow(2.0, 52);

        // Adjust the sign if necessary
        if(negative)
            significand = -significand;
    }*/

    public static void Frexp(double value, out double significand, out int exponent)
    {
        significand = value;
        long bits = BitConverter.DoubleToInt64Bits(significand);
        int exp = (int)((bits & DBL_EXP_MASK) >> DBL_MANT_BITS);
        exponent = 0;

        if (exp == 0x7ff || significand == 0D)
            significand += significand;
        else
        {
            // Not zero and finite.
            exponent = exp - 1022;
            if (exp == 0)
            {
                // Subnormal, scale significand so that it is in [1, 2).
                significand *= BitConverter.Int64BitsToDouble(0x4350000000000000L); // 2^54
                bits = BitConverter.DoubleToInt64Bits(significand);
                exp = (int)((bits & DBL_EXP_MASK) >> DBL_MANT_BITS);
                exponent = exp - 1022 - 54;
            }
            // Set exponent to -1 so that significand is in [0.5, 1).
            significand = BitConverter.Int64BitsToDouble((bits & DBL_EXP_CLR_MASK) | 0x3fe0000000000000L);
        }
    }
}

public class WarthogExponential
{
    public uint negExp { get; private set; } = 0; // negative exponent of 2
    public uint data { get; private set; } = 0x80000000;

    public WarthogExponential() { }

    public WarthogExponential(ReadOnlySpan<byte> hash)
    {
        negExp += 1; // we are considering hashes as number in (0,1), padded with infinite amount of trailing 1's
        int i = 0;
        for(; i < hash.Length; ++i)
        {
            if(hash[i] != 0)
                break;
            negExp += 8;
        }

        ulong tmpData = 0;
        for(int j = 0; ; ++j)
        {
            if(i < hash.Length)
                tmpData |= hash[i++];
            else
                tmpData |= 0xFFu; // "infinite amount of trailing 1's"

            if(j >= 3)
                break;
            tmpData <<= 8;
        }

        while((tmpData & 0x80000000ul) == 0)
        {
            negExp += 1;
            tmpData <<= 1;
        }

        tmpData *= (ulong)data;
        if(tmpData >= (ulong)(1ul << 63))
        {
            tmpData >>= 1;
            negExp -= 1;
        }

        tmpData >>= 31;

        data = (uint)tmpData;
    }
}

public class WarthogTarget
{    
    public bool IsJanusHash { get; private set; } = true;
    public uint data { get; private set; } = 0u;

    public WarthogTarget(uint data, bool isJanusHash = true)
    {
        this.data = data;
        this.IsJanusHash = isJanusHash;
    }

    public WarthogTarget(byte[] data, bool isJanusHash = true)
    {
        this.data = uint.Parse(data.ToHexString(), NumberStyles.HexNumber);
        this.IsJanusHash = isJanusHash;
    }

    public WarthogTarget(double difficulty, bool isJanusHash = true)
    {
        if(difficulty < 1.0)
            difficulty = 1.0;

        this.IsJanusHash = isJanusHash;

        WarthogUtils.Frexp(difficulty, out var coef, out var exp);
        double inv = 1 / coef;
        uint zeros;
        uint digits;

        if(!this.IsJanusHash)
        {
            if(exp - 1 >= 256 - 24)
            {
                data = WarthogConstants.HardestTargetHost;
                return;
            }

            zeros = (uint)(exp - 1);
            if(inv == 2.0)
            {
                Set(zeros, 0x00FFFFFF);
            }
            else
            {
                digits = (uint)Math.Floor(Math.ScaleB(inv, 23));
                if(digits < 0x00800000)
                    Set(zeros, 0x00800000);
                else if(digits > 0x00FFFFFF)
                    Set(zeros, 0x00FFFFFF);
                else
                    Set(zeros, digits);
            }
        }
        else
        {
            zeros = (uint)(exp - 1);
            if(zeros >= 3 * 256)
            {
                data = WarthogConstants.JanusHashMaxTargetHost;
                return;
            }
            if(inv == 2.0)
            {
                Set(zeros, 0x003fffff);
            }
            else
            {
                digits = (uint)Math.Floor(Math.ScaleB(inv, 21));
                if(digits < 0x00200000)
                    Set(zeros, 0x00200000);
                else if(digits > 0x003fffff)
                    Set(zeros, 0x003fffff);
                else
                    Set(zeros, digits);
            }
        }
    }

    private void Set(uint zeros, uint bytes)
    {
        data = (!this.IsJanusHash) ? (zeros << 24) | bytes : (zeros << 22) | bytes;
    }

    public uint Zeros8()
    {
        return data >> 24;
    }

    public uint Zeros10()
    {
        return data >> 22;
    }

    public uint Bits22()
    {
        return data & 0x003FFFFF;
    }

    public uint Bits24()
    {
        return data & 0x00FFFFFF;
    }

    public double Difficulty()
    {
        int zeros;
        double dbits;

        if(!IsJanusHash)
        {
            zeros = (int)Zeros8();
            dbits = Bits24();
            return Math.Pow(2, zeros + 24) / dbits;
        }
        else
        {
            zeros = (int)Zeros10();
            dbits = Bits22();
            return Math.Pow(2, zeros + 22) / dbits;
        }
    }

    public static bool operator <(WarthogCustomFloat wcf, WarthogTarget wt)
    {
        if(!wt.IsJanusHash)
            return false;
        else
        {
            uint zerosTarget = wt.Zeros10();
            int exp = wcf._exponent;
            if(exp < 0)
                exp = -exp;
            uint zerosHashProduct = (uint)exp;

            if(zerosTarget > zerosHashProduct)
                return false;

            if(zerosTarget < zerosHashProduct)
                return true;

            ulong bits32 = wt.Bits22() << 10;
            return wcf._mantissa < bits32;
        }
    }

    public static bool operator >(WarthogCustomFloat wcf, WarthogTarget wt)
    {
        if(!wt.IsJanusHash)
            return false;
        else
        {
            uint zerosTarget = wt.Zeros10();
            int exp = wcf._exponent;
            if(exp < 0)
                exp = -exp;
            uint zerosHashProduct = (uint)exp;

            if(zerosTarget > zerosHashProduct)
                return true;

            if(zerosTarget < zerosHashProduct)
                return false;

            ulong bits32 = wt.Bits22() << 10;
            return wcf._mantissa > bits32;
        }
    }

    public static bool operator <(ReadOnlySpan<byte> hash, WarthogTarget wt)
    {
        if(!wt.IsJanusHash)
        {
            uint zeros = wt.Zeros8();
            if(zeros > (256 - 4 * 8))
                return false;
            uint bits = wt.Bits24();
            if((bits & 0x00800000) == 0)
                return false; // first digit must be 1
            int zeroBytes = (int)(zeros / 8); // number of complete zero bytes
            int shift = (int)(zeros & 0x07);

            for(int i = 0; i < zeroBytes; ++i)
                if(hash[31 - i] != 0)
                    return false; // here we need zeros

            uint threshold = bits << (8 - shift);
            byte[] dst = hash.ToArray().Skip(28 - zeroBytes).Take(4).ToArray();
            uint candidate = uint.Parse(dst.ToHexString(), NumberStyles.HexNumber);
            if(candidate > threshold)
            {
                return false;
            }
            if(candidate < threshold)
            {
                return true;
            }
            for(int i = 0; i < 28 - zeroBytes; ++i)
                if(hash[i] != 0)
                    return false;
            return true;
        }
        else
        {
            WarthogExponential we = new WarthogExponential(hash);
            uint zerosTarget = wt.Zeros10();
            uint zerosHashProduct = (uint)(we.negExp - 1);

            if(zerosTarget > zerosHashProduct)
                return false;

            if(zerosTarget < zerosHashProduct)
                return true;

            uint bits32 = wt.Bits22() << 10;
            return we.data < bits32;
        }
    }

    public static bool operator >(ReadOnlySpan<byte> hash, WarthogTarget wt)
    {
        if(!wt.IsJanusHash)
        {
            uint zeros = wt.Zeros8();
            if(zeros < (256 - 4 * 8))
                return false;
            uint bits = wt.Bits24();
            if((bits & 0x00800000) != 0)
                return false; // first digit must be 1
            int zeroBytes = (int)(zeros / 8); // number of complete zero bytes
            int shift = (int)(zeros & 0x07);

            for(int i = 0; i < zeroBytes; ++i)
                if(hash[31 - i] == 0)
                    return false; // here we need zeros

            uint threshold = bits << (8 - shift);
            byte[] dst = hash.ToArray().Skip(28 - zeroBytes).Take(4).ToArray();
            uint candidate = uint.Parse(dst.ToHexString(), NumberStyles.HexNumber);
            if(candidate < threshold)
            {
                return false;
            }
            if(candidate > threshold)
            {
                return true;
            }
            for(int i = 0; i < 28 - zeroBytes; ++i)
                if(hash[i] == 0)
                    return false;
            return true;
        }
        else
        {
            WarthogExponential we = new WarthogExponential(hash);
            uint zerosTarget = wt.Zeros10();
            uint zerosHashProduct = (uint)(we.negExp - 1);

            if(zerosTarget > zerosHashProduct)
                return true;

            if(zerosTarget < zerosHashProduct)
                return false;

            uint bits32 = wt.Bits22() << 10;
            return we.data > bits32;
        }
    }
}

// https://github.com/CoinFuMasterShifu/CustomFloat/blob/master/src/custom_float.hpp
[Serializable]
[ComVisible(false)]
public class WarthogCustomFloat : IComparable, IComparable<WarthogCustomFloat>, IDeserializationCallback,
    IEquatable<WarthogCustomFloat>,
    ISerializable
{
    // ---- SECTION:  members supporting exposed properties -------------*
    public int _exponent { get; private set; } = 0;
    public uint _mantissa { get; private set; } = 0;
    public bool _isPositive { get; private set; } = true;

    #region Public Properties

    public long Exponent
    {
        get => (long)this._exponent;
        set
        {
            if(!(value < int.MaxValue && value > int.MinValue))
                throw new Exception($"Invalid value for Exponent: {value} < {int.MaxValue} && {value} > {int.MinValue}");

            this._exponent = (int)value;
        }
    }

    public ulong Mantissa
    {
        get => (ulong)this._mantissa;
        set
        {
            if(!(value < (ulong)(1ul << 32) && value != 0))
                throw new Exception($"Invalid value for Mantissa: {value} < {(ulong)(1ul << 32)} && {value} != 0");

            this._mantissa = (uint)value;
        }
    }

    public bool IsPositive
    {
        get => this._isPositive;
        set
        {
            this._isPositive = value;
        }
    }

    #endregion Public Properties

    // ---- SECTION: public instance methods --------------*

    #region Public Instance Methods

    private void SetAssert(long exponent, ulong mantissa)
    {
        this.Exponent = exponent;

        if(mantissa == 0)
            this._mantissa = 0;
        else
            this.Mantissa = mantissa;
    }

    public void ShiftLeft(long exponent, ulong mantissa)
    {
        while(mantissa < 0x80000000ul)
        {
            mantissa <<= 1;
            exponent -= 1;
        }

        this.SetAssert(exponent, mantissa);
    }

    public void ShiftRight(long exponent, ulong mantissa)
    {
        while(mantissa >= (1ul << 32))
        {
            mantissa >>= 1;
            exponent += 1;
        }

        this.SetAssert(exponent, mantissa);
    }

    public override bool Equals(object obj)
    {
        return obj is WarthogCustomFloat customfloat && Equals(customfloat);
    }

    public override int GetHashCode()
    {
        return ((double)this).GetHashCode();
    }

    // IComparable
    int IComparable.CompareTo(object obj)
    {
        if(obj == null)
            return 1;
        if(obj is not WarthogCustomFloat customfloat)
            throw new ArgumentException("Argument must be of type WarthogCustomFloat", "obj");
        return Compare(this, customfloat);
    }

    // IComparable<WarthogCustomFloat>
    public int CompareTo(WarthogCustomFloat other)
    {
        return Compare(this, other);
    }

    // Object.ToString (x * 2^n)
    public override string ToString()
    {
        double r = (double)this._mantissa / (ulong)(1ul << 32);

        if(!this._isPositive)
            r = -r;

        var ret = new StringBuilder();
        ret.Append(r.ToString("F", CultureInfo.InvariantCulture));
        ret.Append(" * 2^");
        ret.Append(this._exponent.ToString("D", CultureInfo.InvariantCulture));
        return ret.ToString();
    }

    // IEquatable<WarthogCustomFloat>
    // a/b = c/d, if ad = bc
    public bool Equals(WarthogCustomFloat other)
    {
        if(this._exponent == other._exponent && this._mantissa == other._mantissa)
            return this._isPositive == other._isPositive;

        long xMantissa = (long)this._mantissa;
        if(!this._isPositive)
            xMantissa = -xMantissa;
        long yMantissa = other._mantissa;
        if(!other._isPositive)
            yMantissa = -yMantissa;

        return xMantissa * other._exponent == this._exponent * yMantissa;
    }

    #endregion Public Instance Methods

    // -------- SECTION: constructors -----------------*

    #region Constructors

    public WarthogCustomFloat(int exponent, uint mantissa, bool isPositive)
    {
        this._exponent = exponent;
        this._mantissa = mantissa;
        this._isPositive = isPositive;
    }

    public WarthogCustomFloat(ReadOnlySpan<byte> hash)
    {
        this._isPositive = true;
        int exponent = 0;
        int i = 0;
        for(; i < hash.Length; ++i)
        {
            if(hash[i] != 0)
                break;
            exponent -= 8;
        }

        ulong tmpData = 0;

        for(int j = 0; ; ++j)
        {
            if(i < hash.Length)
                tmpData |= hash[i++];
            else
                tmpData |= 0xFFu; // "infinite amount of trailing 1's"

            if(j >= 3)
                break;

            tmpData <<= 8;
        }

        ShiftLeft(exponent, tmpData);
    }

    public WarthogCustomFloat(double d)
    {
        if(d == 0)
        {
            this._exponent = 0;
            this._mantissa = 0;
            this._isPositive = true;
        }
        else
        {
            WarthogUtils.Frexp(d, out var r, out var e);

            bool isPositive = r >= 0;
            if(r < 0)
                r = -r;

            r *= (ulong)(1ul << 32);
            ulong m = (ulong)Math.Ceiling(r);

            this._exponent = e;
            this.Mantissa = m;
            this._isPositive = isPositive;
        }
    }

    public WarthogCustomFloat(int mantissa)
    {
        if(mantissa == 0)
        {
            this._exponent = 0;
            this._mantissa = 0;
            this._isPositive = true;
        }
        else
        {
            this.IsPositive = mantissa >= 0;
            
            if(mantissa < 0)
                mantissa = -mantissa;

            ulong tmpData = (ulong)mantissa;

            ShiftLeft(32, tmpData);
        }
    }

    public WarthogCustomFloat(long exponent, bool isPositive)
    {
        if(exponent >= int.MaxValue || exponent <= int.MinValue)
            throw new ArgumentException($"Invalid value for exponent: {exponent} < {int.MaxValue} && {exponent} > {int.MinValue}");

        this.Exponent = exponent + 1;
        this.Mantissa = 0x80000000ul;
        this.IsPositive = isPositive;
    }

    #endregion Constructors

    // -------- SECTION: public static methods -----------------*

    #region Public Static Methods

    public static WarthogCustomFloat Negate(WarthogCustomFloat wcf)
    {
        return new(wcf._exponent, wcf._mantissa, !wcf._isPositive);
    }

    public static WarthogCustomFloat Add(WarthogCustomFloat wcf1, WarthogCustomFloat wcf2)
    {
        return wcf1 + wcf2;
    }

    public static WarthogCustomFloat Subtract(WarthogCustomFloat wcf1, WarthogCustomFloat wcf2)
    {
        return wcf1 - wcf2;
    }

    public static WarthogCustomFloat Multiply(WarthogCustomFloat wcf1, WarthogCustomFloat wcf2)
    {
        return wcf1 * wcf2;
    }

    public static WarthogCustomFloat Divide(WarthogCustomFloat wcf1, WarthogCustomFloat wcf2)
    {
        return wcf1 / wcf2;
    }

    public static WarthogCustomFloat Pow(WarthogCustomFloat wcf1, WarthogCustomFloat wcf2)
    {
        return Pow2(wcf2 * Log2(wcf1));
    }

    public static WarthogCustomFloat Zero()
    {
        return new(0, 0, true);
    }

    public static WarthogCustomFloat One()
    {
        return new(0, 1, true);
    }

    public static int Compare(WarthogCustomFloat wcf1, WarthogCustomFloat wcf2)
    {
        return ((double)wcf1).CompareTo((double)wcf2);
    }

    #endregion Public Static Methods

    #region Operator Overloads

    public static bool operator ==(WarthogCustomFloat wcf1, WarthogCustomFloat wcf2)
    {
        return wcf1.Equals(wcf2);
    }

    public static bool operator !=(WarthogCustomFloat wcf1, WarthogCustomFloat wcf2)
    {
        return !wcf1.Equals(wcf2);
    }

    public static bool operator <(WarthogCustomFloat wcf1, WarthogCustomFloat wcf2)
    {
        int expWcf2 = wcf2._exponent;
        if(expWcf2 < 0)
            expWcf2 = -expWcf2;
        uint zerosWcf2 = (uint)expWcf2;

        int expWcf1 = wcf1._exponent;
        if(expWcf1 < 0)
            expWcf1 = -expWcf1;
        uint zerosWcf1 = (uint)expWcf1;

        if(zerosWcf1 < zerosWcf2)
            return false;

        if(zerosWcf1 > zerosWcf2)
            return true;

        return wcf1._mantissa < wcf2._mantissa;
    }

    public static bool operator <=(WarthogCustomFloat wcf1, WarthogCustomFloat wcf2)
    {
        int expWcf2 = wcf2._exponent;
        if(expWcf2 < 0)
            expWcf2 = -expWcf2;
        uint zerosWcf2 = (uint)expWcf2;

        int expWcf1 = wcf1._exponent;
        if(expWcf1 < 0)
            expWcf1 = -expWcf1;
        uint zerosWcf1 = (uint)expWcf1;

        if(zerosWcf1 < zerosWcf2)
            return false;
    
        if(zerosWcf1 >= zerosWcf2)
            return true;

        return wcf1._mantissa <= wcf2._mantissa;
    }

    public static bool operator >(WarthogCustomFloat wcf1, WarthogCustomFloat wcf2)
    {
        return !(wcf1 < wcf2);
    }

    public static bool operator >=(WarthogCustomFloat wcf1, WarthogCustomFloat wcf2)
    {
        return !(wcf1 <= wcf2);
    }

    public static WarthogCustomFloat operator +(WarthogCustomFloat wcf)
    {
        return wcf;
    }

    public static WarthogCustomFloat operator -(WarthogCustomFloat wcf)
    {
        return new(wcf._exponent, wcf._mantissa, !wcf._isPositive);
    }

    public static WarthogCustomFloat operator ++(WarthogCustomFloat wcf)
    {
        return wcf + One();
    }

    public static WarthogCustomFloat operator --(WarthogCustomFloat wcf)
    {
        return wcf - One();
    }

    public static WarthogCustomFloat operator +(WarthogCustomFloat wcf1, WarthogCustomFloat wcf2)
    {
        WarthogCustomFloat wcf3 = new(wcf1._exponent, wcf1._mantissa, wcf1._isPositive);
        int e1 = wcf1._exponent;
        int e2 = wcf2._exponent;

        if(wcf1._mantissa == 0)
        {
            wcf3._exponent = wcf2._exponent;
            wcf3._mantissa = wcf2._mantissa;
            wcf3._isPositive = wcf2._isPositive;

            return wcf3;
        }

        if(wcf2._mantissa == 0)
            return wcf3;

        if(e1 < e2)
            return wcf2 + wcf1;

        if(e1 - e2 >= 64)
            return wcf3;

        ulong tmp = wcf1._mantissa;
        ulong operand = (ulong)wcf2._mantissa >> (e1 - e2);

        if(wcf1._isPositive == wcf2._isPositive)
        {
            tmp += operand;
            
            wcf3.ShiftRight(e1, tmp);
        }
        else
        {
            if(operand == tmp)
                wcf3._mantissa = 0;
            else if(operand > tmp)
            {
                wcf3._isPositive = wcf2._isPositive; // change sign
                wcf3.ShiftLeft(e2, operand - tmp);
            }
            else
                wcf3.ShiftLeft(e1, tmp - operand);
        }

        return wcf3;
    }

    public static WarthogCustomFloat operator -(WarthogCustomFloat wcf1, WarthogCustomFloat wcf2)
    {
        WarthogCustomFloat wcf3 = new(wcf2._exponent, wcf2._mantissa, !wcf2._isPositive);

        return wcf1 + wcf3;
    }

    public static WarthogCustomFloat operator *(WarthogCustomFloat wcf1, WarthogCustomFloat wcf2)
    {
        WarthogCustomFloat wcf3 = new(wcf1._exponent, wcf1._mantissa, wcf1._isPositive);
        if(wcf1._mantissa == 0 || wcf2._mantissa == 0)
        {
            wcf3._mantissa = 0;
            return wcf3;
        }

        wcf3.IsPositive = wcf1._isPositive == wcf2._isPositive;
        int e1 = wcf1._exponent;
        int e2 = wcf2._exponent;
        long e = (long)(e1 + e2);
        ulong tmp = (ulong)wcf1._mantissa * wcf2._mantissa;

        if(tmp < (1ul << 63))
        {
            e -= 1;
            tmp <<= 1;
        }

        tmp >>= 32;
        wcf3.SetAssert(e, tmp);

        return wcf3;
    }

    public static WarthogCustomFloat operator /(WarthogCustomFloat wcf1, WarthogCustomFloat wcf2)
    {
        WarthogCustomFloat wcf3 = new(wcf1._exponent, wcf1._mantissa, wcf1._isPositive);
        if (wcf2._mantissa == 0)
            throw new DivideByZeroException("Attempt to divide by zero.");

        if (wcf1._mantissa == 0)
        {
            wcf3._mantissa = 0;
            return wcf3;
        }

        wcf3.IsPositive = wcf1._isPositive == wcf2._isPositive;
        int e1 = wcf1._exponent;
        int e2 = wcf2._exponent;
        long e = (long)(e1 - e2);

        ulong dividend = (ulong)wcf1._mantissa;
        ulong divisor = (ulong)wcf2._mantissa;

        ulong tmp = (ulong)Math.Ceiling((double)(dividend / divisor));

        wcf3.SetAssert(e, tmp);

        return wcf3;
    }

    #endregion Operator Overloads

    // ----- SECTION: explicit conversions from WarthogCustomFloat to numeric base types  ----------------*

    #region explicit conversions from WarthogCustomFloat

    public static explicit operator double(WarthogCustomFloat value)
    {
        if(value._mantissa == 0)
            return 0;

        double r = (double)value._mantissa / (ulong)(1ul << 32);

        if(!value._isPositive)
            r = -r;

        // return Math.Pow(2, value._exponent) * r;
        return Math.ScaleB(r, value._exponent);
    }

    #endregion explicit conversions from WarthogCustomFloat

    // ----- SECTION: implicit conversions from numeric base types to WarthogCustomFloat  ----------------*

    #region implicit conversions to WarthogCustomFloat

    #endregion implicit conversions to WarthogCustomFloat

    // ----- SECTION: private serialization instance methods  ----------------*

    #region serialization

    void IDeserializationCallback.OnDeserialization(object sender)
    {
        try
        {
            // verify that the deserialized number is well formed
            SetAssert(this._exponent, this._mantissa);
        }
        catch(ArgumentException e)
        {
            throw new SerializationException("invalid serialization data", e);
        }
    }

    void ISerializable.GetObjectData(SerializationInfo info, StreamingContext context)
    {
        if(info == null)
            throw new ArgumentNullException(nameof(info));

        info.AddValue("Exponent", this._exponent);
        info.AddValue("Mantissa", this._mantissa);
        info.AddValue("IsPositive", this._isPositive);
    }

    private WarthogCustomFloat(SerializationInfo info, StreamingContext context)
    {
        if(info == null)
            throw new ArgumentNullException(nameof(info));

        this._exponent = (int) info.GetValue("Exponent", typeof(int));
        this._mantissa = (uint) info.GetValue("Mantissa", typeof(uint));
        this._isPositive = (bool) info.GetValue("IsPositive", typeof(bool));
    }

    #endregion serialization

    // ----- SECTION: private instance utility methods ----------------*

    #region instance helper methods

    #endregion instance helper methods

    // ----- SECTION: private static utility methods -----------------*

    #region static helper methods

    public static WarthogCustomFloat Pow2(WarthogCustomFloat wcf)
    {
        WarthogCustomFloat wcf1;

        if(wcf._mantissa == 0)
        {
            wcf1 = new(1);
            return wcf1;
        }

        int e_x = wcf._exponent;
        uint m = wcf._mantissa;

        if(e_x == 32)
        {
            if(wcf._isPositive)
            {
                wcf1 = new((long)m, true);
                return wcf1;
            }

            wcf1 = new(-((long)m), true);
            return wcf1;
        }
        else
        {
            if(e_x > 0)
            {
                long e = (long)(m >> (32 - e_x));
                uint m_frac = (uint)(m << e_x);
                if(m_frac == 0)
                {
                    if(wcf._isPositive)
                    {
                        wcf1 = new(e, true);
                        return wcf1;
                    }

                    wcf1 = new(e, true);
                    wcf1.Exponent = -wcf1.Exponent;
                    wcf1.Exponent += 2;

                    return wcf1;
                }

                WarthogCustomFloat frac = Zero();
                frac.ShiftLeft(0, m_frac);

                if(wcf._isPositive)
                {
                    wcf1 = Pow2Fraction(frac);
                    wcf1.Exponent += e;

                    return wcf1;
                }

                wcf1 = Pow2Fraction(new WarthogCustomFloat(1) - frac);
                wcf1.Exponent += e - 1;
                wcf1.Exponent = -wcf1.Exponent;

                return wcf1;
            }
            else
            {
                if(wcf._isPositive)
                    return Pow2Fraction(wcf);

                wcf1 = Pow2Fraction(new WarthogCustomFloat(1) + wcf);
                wcf1.Exponent = -wcf1.Exponent;
                wcf1.Exponent += 1;

                return wcf1;
            }
        }
    }

    public static WarthogCustomFloat Log2(WarthogCustomFloat wcf)
    {
        WarthogCustomFloat wcf1 = new(wcf._exponent, wcf._mantissa, wcf._isPositive);
        int e = wcf._exponent;
        wcf1._exponent = 0;
        WarthogCustomFloat c0 = new(1, 2872373668, true); // = 1.33755322
        WarthogCustomFloat c1 = new(3, 2377545675, false); // = -4.42852392
        WarthogCustomFloat c2 = new(3, 3384280813, true); // = 6.30371424
        WarthogCustomFloat c3 = new(2, 3451338727, false); // = -3.21430967
        WarthogCustomFloat d = c3 + wcf1 * (c2 + wcf1 * (c1 + wcf1 * c0));

        return new WarthogCustomFloat(e) + d;
    }

    public static WarthogCustomFloat Pow2Fraction(WarthogCustomFloat wcf)
    {
        WarthogCustomFloat wcf1 = new(wcf._exponent, wcf._mantissa, wcf._isPositive);
        // I have modified constants from here: https://github.com/nadavrot/fast_log/blob/83bd112c330976c291300eaa214e668f809367ab/src/exp_approx.cc#L18
        // such that they don't compute the euler logartihm but logarithm to base 2.
        WarthogCustomFloat c0 = new(-3, 3207796260, true); // = 0.09335915850659268
        WarthogCustomFloat c1 = new(-2, 3510493713, true); // = 0.2043376277254389
        WarthogCustomFloat c2 = new(0, 3014961390, true); // = 0.7019754011048444
        WarthogCustomFloat c3 = new(1, 2147933481, true); // = 1.00020947
        WarthogCustomFloat d = c3 + wcf1 * (c2 + wcf1 * (c1 + wcf1 * c0));

        return d;
    }

    #endregion static helper methods
}