namespace Miningcore.Blockchain.Kaspa.Configuration;

public class KaspaPaymentProcessingConfigExtra
{
    /// <summary>
    /// Password for unlocking wallet
    /// </summary>
    public string WalletPassword { get; set; }

    /// <summary>
    /// Minimum block confirmations
    /// KAS minimum confirmation can change over time so please always study all those different changes very wisely: https://github.com/kaspanet/rusty-kaspa/blob/master/wallet/core/src/utxo/settings.rs
    /// Default: (mainnet: 120, testnet: 110)
    /// </summary>
    public int? MinimumConfirmations { get; set; }

    /// <summary>
    /// kaspawallet daemon version which enables MaxFee (KASPA: "v0.12.18-rc5")
    /// </summary>
    public string VersionEnablingMaxFee { get; set; }

    /// <summary>
    /// Maximum amount you're willing to pay (in SOMPI)
    /// Default: 20000 (0.0002 KAS)
    /// </summary>
    public ulong? MaxFee { get; set; }
}