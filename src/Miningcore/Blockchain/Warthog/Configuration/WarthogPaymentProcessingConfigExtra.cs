namespace Miningcore.Blockchain.Warthog.Configuration;

public class WarthogPaymentProcessingConfigExtra
{
    /// <summary>
    /// DANGER: The privateKey of your wallet is a very sensitive data, since it can be used for restoring the wallet, please keep it very private at all cost
    /// MANDATORY for sending payments
    /// </summary>
    public string WalletPrivateKey { get; set; }

    /// <summary>
    /// Maximum amount you're willing to pay for transaction fees (in UNIT)
    /// Default: 1
    /// </summary>
    public decimal? MaximumTransactionFees { get; set; }

    /// <summary>
    /// True to exempt transaction fees from miner rewards
    /// </summary>
    public bool KeepTransactionFees { get; set; }

    /// <summary>
    /// Minimum block confirmations
    /// Default: "Mainnet" (120) - "Testnet" (110)
    /// </summary>
    public int? MinimumConfirmations { get; set; }
    
    /// <summary>
    /// Maximum number of payouts which can be done in parallel
    /// Default: 2
    /// </summary>
    public int? MaxDegreeOfParallelPayouts { get; set; }
}