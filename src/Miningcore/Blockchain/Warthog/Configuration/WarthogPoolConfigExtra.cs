using Miningcore.Configuration;

namespace Miningcore.Blockchain.Warthog.Configuration;

public class WarthogPoolConfigExtra
{
    /// <summary>
    /// Maximum number of tracked jobs.
    /// Default: 4
    /// </summary>
    public int? MaxActiveJobs { get; set; }

    public int? ExtraNonce1Size { get; set; }
}