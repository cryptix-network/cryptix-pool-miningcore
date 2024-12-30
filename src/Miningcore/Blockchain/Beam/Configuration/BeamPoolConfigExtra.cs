using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Miningcore.Blockchain.Beam.Configuration;

public class BeamPoolConfigExtra
{
    /// <summary>
    /// Maximum number of tracked jobs.
    /// Default: 4 - you should increase this value if beam-node <miner_job_latency> is higher than 300ms
    /// </summary>
    public int? MaxActiveJobs { get; set; }
}
