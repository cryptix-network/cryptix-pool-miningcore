using System.Globalization;
using System.Numerics;

namespace Miningcore.Blockchain.Handshake;

public static class HandshakeConstants
{
    public const int BlockHeaderSize = 236;

    public const decimal DollarydoosPerHandshake = 100000000;
    public const string WalletDaemonCategory = "wallet";
    public const string WalletDefaultName = "primary";
    public const string WalletDefaultAccount = "default";

    public static readonly BigInteger Diff1 = BigInteger.Parse("00000000ffff0000000000000000000000000000000000000000000000000000", NumberStyles.HexNumber);
    public const int CoinbaseMinConfimations = 102;
}

public static class HandshakeWalletCommands
{
    public const string GetWalletInfo = "getwalletinfo";
    public const string GetBalance = "getbalance";
    public const string GetTransaction = "gettransaction";
    public const string GetAddressesByAccount = "getaddressesbyaccount";
    public const string SendMany = "sendmany";
    public const string SendToAddress = "sendtoaddress";
    public const string SelectWallet = "selectwallet"; // select wallet to use
    public const string WalletLock = "walletlock";
    public const string WalletPassPhrase = "walletpassphrase"; // unlock wallet
}