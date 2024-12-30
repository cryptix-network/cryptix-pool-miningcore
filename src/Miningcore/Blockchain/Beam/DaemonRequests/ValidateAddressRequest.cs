using Newtonsoft.Json;

namespace Miningcore.Blockchain.Beam.DaemonRequests;

public class ValidateAddressRequest
{
    [JsonProperty("address")]
    public string Address { get; set; }
}