using System.Text.Json.Serialization;

namespace Miningcore.Blockchain.Conceal.DaemonResponses;

public class GetStatusResponse
{
    [JsonPropertyName("addressCount")]
    public int AddressCount { get; set; }

    [JsonPropertyName("blockCount")]
    public ulong BlockCount { get; set; }

    [JsonPropertyName("depositCount")]
    public int DepositCount { get; set; }

    [JsonPropertyName("knownBlockCount")]
    public ulong KnownBlockCount { get; set; }

    [JsonPropertyName("lastBlockHash")]
    public string LastBlockHash { get; set; }

    [JsonPropertyName("peerCount")]
    public int PeerCount { get; set; }

    [JsonPropertyName("transactionCount")]
    public ulong TransactionCount { get; set; }
}