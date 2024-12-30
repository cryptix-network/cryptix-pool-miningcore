using System.Text.Json.Serialization;

namespace Miningcore.Blockchain.Warthog.DaemonResponses;

public class GetPeersChain
{
    [JsonPropertyName("length")]
    public ulong Height { get; set; }
}

public class GetPeersResponse
{
    public GetPeersChain Chain { get; set; }
}
