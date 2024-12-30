using System.Text.Json.Serialization;

namespace Miningcore.Blockchain.Warthog.DaemonResponses;

public class GetNetworkHashrateData
{
    [JsonPropertyName("lastNBlocksEstimate")]
    public double Hashrate { get; set; }
}

public class GetNetworkHashrateResponse : WarthogResponseBase
{
    public GetNetworkHashrateData Data { get; set; }
}

