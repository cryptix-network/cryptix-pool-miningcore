using System.Globalization;
using System.Numerics;
using System.Text.RegularExpressions;

// ReSharper disable InconsistentNaming

namespace Miningcore.Blockchain.Kaspa;

public static class KaspaConstants
{
    public const string WalletDaemonCategory = "wallet";
    
    public const int Diff1TargetNumZero = 31;
    public static readonly BigInteger Diff1b = BigInteger.Parse("00ffff0000000000000000000000000000000000000000000000000000000000", NumberStyles.HexNumber);
    public static BigInteger Diff1 = BigInteger.Pow(2, 256);
    public static BigInteger Diff1Target = BigInteger.Pow(2, 255) - 1;
    public static readonly double Pow2xDiff1TargetNumZero = Math.Pow(2, Diff1TargetNumZero);
    public static BigInteger MinHash = BigInteger.Divide(Diff1, Diff1Target);
    public const int ExtranoncePlaceHolderLength = 8;
    public static int NonceLength = 16;
    
    // KAS smallest unit is called SOMPI: https://github.com/kaspanet/kaspad/blob/master/util/amount.go
    public const decimal SmallestUnit = 100000000;

    public static readonly Regex RegexUserAgentBzMiner = new("bzminer", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    public static readonly Regex RegexUserAgentIceRiverMiner = new("iceriverminer", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    public static readonly Regex RegexUserAgentGodMiner = new("godminer", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    public static readonly Regex RegexUserAgentGoldShell = new("(goldshell|bzminer)", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    public static readonly Regex RegexUserAgentTNNMiner = new("tnn-miner", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    
    public const string CoinbaseBlockHash = "BlockHash";
    public const string CoinbaseProofOfWorkHash = "ProofOfWorkHash";
    public const string CoinbaseHeavyHash = "HeavyHash";
    
    public const string ProtobufDaemonRpcServiceName = "protowire.RPC";
    public const string ProtobufWalletRpcServiceName = "kaspawalletd.kaspawalletd";
    
    public const byte PubKeyAddrID = 0x00;
    public const byte PubKeyECDSAAddrID = 0x01;
    public const byte ScriptHashAddrID = 0x08;
    public static readonly Dictionary<byte, string> KaspaAddressType = new Dictionary<byte, string>
    {
        { PubKeyAddrID, "Public Key Address" },
        { PubKeyECDSAAddrID, "Public Key ECDSA Address" },
        { ScriptHashAddrID, "Script Hash Address" },
    };
    public const int PublicKeySize = 32;
    public const int PublicKeySizeECDSA = 33;
    public const int Blake2bSize256 = 32;
}

public static class KarlsencoinConstants
{   
    public const ulong FishHashForkHeightTestnet = 0;
    public const ulong FishHashPlusForkHeightTestnet = 43200;
    public const ulong FishHashPlusForkHeightMainnet = 26962009;
}

// Pyrin is definitely a scam, use at your own risk
public static class PyrinConstants
{   
    public const ulong Blake3ForkHeight = 1484741;
}

public static class SpectreConstants
{
    public const int Diff1TargetNumZero = 7;
    public static readonly BigInteger Diff1b = BigInteger.Parse("00ffff0000000000000000000000000000000000000000000000000000000000", NumberStyles.HexNumber);
    public static readonly double Pow2xDiff1TargetNumZero = Math.Pow(2, Diff1TargetNumZero);
    public static BigInteger MinHash = BigInteger.One;
}

public enum KaspaBech32Prefix
{
    Unknown = 0,
    KaspaMain,
    KaspaDev,
    KaspaTest,
    KaspaSim
}