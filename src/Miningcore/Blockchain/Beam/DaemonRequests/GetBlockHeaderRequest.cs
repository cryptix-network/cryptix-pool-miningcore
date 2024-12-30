using Newtonsoft.Json;

namespace Miningcore.Blockchain.Beam.DaemonRequests;

public class GetBlockHeaderRequest
{
    [JsonProperty("height")]
    public ulong Height { get; set; }
}