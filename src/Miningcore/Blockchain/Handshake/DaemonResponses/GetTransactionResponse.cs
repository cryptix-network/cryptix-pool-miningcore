using Newtonsoft.Json;

namespace Miningcore.Blockchain.Handshake.DaemonResponses;

public class HandshakeTransactionDetails
{
    public string Account { get; set; }
    public string Address { get; set; }
    public string Category { get; set; }
    public decimal Amount { get; set; }
    public string Label { get; set; }
    public int Vout { get; set; }
}

public class HandshakeTransaction
{
    public decimal Amount { get; set; }
    public string BlockHash { get; set; }
    public long BlockIndex { get; set; }
    public ulong BlockTime { get; set; }
    public string TxId { get; set; }
    public string[] WalletConflicts { get; set; }
    public ulong Time { get; set; }
    public ulong TimeReceived { get; set; }

    [JsonProperty("bip125-replaceable")]
    public string Bip125Replaceable { get; set; }

    public HandshakeTransactionDetails[] Details { get; set; }
}
