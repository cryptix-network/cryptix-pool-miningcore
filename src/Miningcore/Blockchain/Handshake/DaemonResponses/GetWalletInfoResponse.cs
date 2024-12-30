namespace Miningcore.Blockchain.Handshake.DaemonResponses;

public class WalletInfo
{
    public string WalletId { get; set; }
    public uint WalletVersion { get; set; }
    // Unconfimed balance can not be trusted, that's why it's not listed here
    public decimal Balance { get; set; }

    public ulong TxCount { get; set; }
    public ulong Height { get; set; }
}