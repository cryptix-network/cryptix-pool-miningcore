using Miningcore.Mining;

namespace Miningcore.Blockchain.Kaspa;

public class KaspaWorkerContext : WorkerContextBase
{
    /// <summary>
    /// Usually a wallet address
    /// </summary>
    public override string Miner { get; set; }

    /// <summary>
    /// Arbitrary worker identififer for miners using multiple rigs
    /// </summary>
    public override string Worker { get; set; }

    /// <summary>
    /// Unique value assigned per worker
    /// </summary>
    public string ExtraNonce1 { get; set; }
    
    /// <summary>
    /// Some mining software require job to be sent in a specific way, we need to be able to identify them
    /// Default: false
    /// </summary>
    public bool IsLargeJob { get; set; } = false;

    public List<KaspaJob> validJobs { get; set; } = new();

    public void AddJob(KaspaJob job, int maxActiveJobs)
    {
        validJobs.Insert(0, job);

        while(validJobs.Count > maxActiveJobs)
            validJobs.RemoveAt(validJobs.Count - 1);
    }
}