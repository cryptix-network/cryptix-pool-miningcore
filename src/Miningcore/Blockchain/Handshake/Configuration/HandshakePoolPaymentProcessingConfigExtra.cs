namespace Miningcore.Blockchain.Handshake.Configuration;

public class HandshakePoolPaymentProcessingConfigExtra
{
    /// <summary>
    /// Name of the wallet to use
    /// Default: "primary"
    /// </summary>
    public string WalletName { get; set; }

    /// <summary>
    /// Name of the wallet account to use
    /// Default: "default"
    /// </summary>
    public string WalletAccount { get; set; }

    /// <summary>
    /// Password for unlocking wallet
    /// </summary>
    public string WalletPassword { get; set; }

    /// <summary>
    /// if True, miners pay payment tx fees
    /// </summary>
    public bool MinersPayTxFees { get; set; }
}