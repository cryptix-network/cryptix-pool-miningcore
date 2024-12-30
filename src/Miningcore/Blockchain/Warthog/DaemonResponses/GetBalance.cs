using System.Text.Json.Serialization;

namespace Miningcore.Blockchain.Warthog.DaemonResponses;

public class WarthogBalanceData
{
    [JsonPropertyName("accountId")]
    public ulong AccountId { get; set; }

    public string Address { get; set; }

    [JsonPropertyName("balanceE8")]
    public ulong Balance { get; set; }
}

public class WarthogBalance : WarthogResponseBase
{
    public WarthogBalanceData Data { get; set; }
}
