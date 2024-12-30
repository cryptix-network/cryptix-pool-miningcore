using System.Numerics;
using Miningcore.Serialization;
using Newtonsoft.Json;

namespace Miningcore.Blockchain.Beam.DaemonResponses;

public class BeamBlockTemplate
{
    [JsonProperty("id")]
    public string JobId { get; set; }
    
    [JsonProperty("height")]
    public ulong Height { get; set; }
    
    public double Difficulty { get; set; }
    
    [JsonProperty("difficulty")]
    public long PackedDifficulty { get; set; }
    
    public string Input { get; set; }
    
    // Beamhash version
    // 0: Beam Hash I
    // 1: Beam Hash II
    // 2: Beam Hash III
    public int PowType { get; set; } = 0;
}