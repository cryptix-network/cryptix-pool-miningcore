using System.Numerics;
using System.Reactive;
using System.Reactive.Linq;
using System.Reactive.Threading.Tasks;
using Autofac;
using AutoMapper;
using Microsoft.IO;
using Miningcore.Blockchain.Bitcoin;
using Miningcore.Blockchain.Kaspa.Configuration;
using Miningcore.Configuration;
using Miningcore.Extensions;
using Miningcore.JsonRpc;
using Miningcore.Messaging;
using Miningcore.Mining;
using Miningcore.Nicehash;
using Miningcore.Notifications.Messages;
using Miningcore.Persistence;
using Miningcore.Persistence.Repositories;
using Miningcore.Stratum;
using Miningcore.Time;
using Miningcore.Util;
using Newtonsoft.Json;
using static Miningcore.Util.ActionUtils;

namespace Miningcore.Blockchain.Kaspa;

[CoinFamily(CoinFamily.Kaspa)]
public class KaspaPool : PoolBase
{
    public KaspaPool(IComponentContext ctx,
        JsonSerializerSettings serializerSettings,
        IConnectionFactory cf,
        IStatsRepository statsRepo,
        IMapper mapper,
        IMasterClock clock,
        IMessageBus messageBus,
        RecyclableMemoryStreamManager rmsm,
        NicehashService nicehashService) :
        base(ctx, serializerSettings, cf, statsRepo, mapper, clock, messageBus, rmsm, nicehashService)
    {
    }

    protected object[] currentJobParams;
    protected KaspaJobManager manager;
    private KaspaPoolConfigExtra extraPoolConfig;
    private KaspaCoinTemplate coin;
    
    protected virtual async Task OnSubscribeAsync(StratumConnection connection, Timestamped<JsonRpcRequest> tsRequest, CancellationToken ct)
    {
        var request = tsRequest.Value;
        var context = connection.ContextAs<KaspaWorkerContext>();

        if(request.Id == null)
            throw new StratumException(StratumError.MinusOne, "missing request id");
            
        // setup worker context
        var requestParams = request.ParamsAs<string[]>();
        context.UserAgent = requestParams.FirstOrDefault()?.Trim();
        context.IsLargeJob = manager.ValidateIsLargeJob(context.UserAgent);

        if(manager.ValidateIsGodMiner(context.UserAgent))
        {
            var data = new object[]
            {
                null,
            }
            .Concat(manager.GetSubscriberData(connection))
            .ToArray();

            await connection.RespondAsync(data, request.Id);
        }
        
        else
        {
            var data = new object[]
            {
                true,
                "KaspaStratum/1.0.0",
            };

            // Nicehash's stupid validator insists on "error" property present
            // in successful responses which is a violation of the JSON-RPC spec
            // [Respect the goddamn standards Nicehack :(]
            var response = new JsonRpcResponse<object[]>(data, request.Id);

            if(context.IsNicehash || manager.ValidateIsGoldShell(context.UserAgent))
            {
                response.Extra = new Dictionary<string, object>();
                response.Extra["error"] = null;
            }

            await connection.RespondAsync(response);
            await connection.NotifyAsync(KaspaStratumMethods.SetExtraNonce, manager.GetSubscriberData(connection));
        }

        context.IsSubscribed = true;
    }

    protected virtual async Task OnAuthorizeAsync(StratumConnection connection, Timestamped<JsonRpcRequest> tsRequest, CancellationToken ct)
    {
        var request = tsRequest.Value;

        if(request.Id == null)
            throw new StratumException(StratumError.MinusOne, "missing request id");
        
        var context = connection.ContextAs<KaspaWorkerContext>();
        
        if(!context.IsSubscribed)
            throw new StratumException(StratumError.NotSubscribed, "subscribe first please, we aren't savages");
        
        var requestParams = request.ParamsAs<string[]>();

        // setup worker context
        context.IsSubscribed = true;
        
        var workerValue = requestParams?.Length > 0 ? requestParams[0] : null;
        var password = requestParams?.Length > 1 ? requestParams[1] : null;
        var passParts = password?.Split(PasswordControlVarsSeparator);

        // extract worker/miner
        var split = workerValue?.Split('.');
        var minerName = split?.FirstOrDefault()?.Trim();
        var workerName = split?.Skip(1).FirstOrDefault()?.Trim() ?? string.Empty;

        // assumes that minerName is an address
        var (kaspaAddressUtility, errorKaspaAddressUtility) = KaspaUtils.ValidateAddress(minerName, manager.Network, coin);
        if (errorKaspaAddressUtility != null)
            logger.Warn(() => $"[{connection.ConnectionId}]{(!string.IsNullOrEmpty(context.UserAgent) ? $"[{context.UserAgent}]" : string.Empty)} Unauthorized worker: {errorKaspaAddressUtility}");
        else
        {
            context.IsAuthorized = true;
            logger.Info(() => $"[{connection.ConnectionId}]{(!string.IsNullOrEmpty(context.UserAgent) ? $"[{context.UserAgent}]" : string.Empty)} worker: {minerName} => {KaspaConstants.KaspaAddressType[kaspaAddressUtility.KaspaAddress.Version()]}");
        }

        context.Miner = minerName;
        context.Worker = workerName;

        if(context.IsAuthorized)
        {
            // Nicehash's stupid validator insists on "error" property present
            // in successful responses which is a violation of the JSON-RPC spec
            // [Respect the goddamn standards Nicehack :(]
            var response = new JsonRpcResponse<object>(context.IsAuthorized, request.Id);

            if(context.IsNicehash || manager.ValidateIsGoldShell(context.UserAgent))
            {
                response.Extra = new Dictionary<string, object>();
                response.Extra["error"] = null;
            }

            // respond
            await connection.RespondAsync(response);
            
            // log association
            logger.Info(() => $"[{connection.ConnectionId}] Authorized worker {workerValue}");

            // extract control vars from password
            var staticDiff = GetStaticDiffFromPassparts(passParts);

            // Nicehash support
            var nicehashDiff = await GetNicehashStaticMinDiff(context, coin.Name, coin.GetAlgorithmName());

            if(nicehashDiff.HasValue)
            {
                if(!staticDiff.HasValue || nicehashDiff > staticDiff)
                {
                    logger.Info(() => $"[{connection.ConnectionId}] Nicehash detected. Using API supplied difficulty of {nicehashDiff.Value}");

                    staticDiff = nicehashDiff;
                }

                else
                    logger.Info(() => $"[{connection.ConnectionId}] Nicehash detected. Using miner supplied difficulty of {staticDiff.Value}");
            }

            // Static diff
            if(staticDiff.HasValue &&
               (context.VarDiff != null && staticDiff.Value >= context.VarDiff.Config.MinDiff ||
                   context.VarDiff == null && staticDiff.Value > context.Difficulty))
            {
                // There are several reports of IDIOTS mining with ridiculous amount of hashrate and maliciously using a very low staticDiff in order to attack mining pools.
                // StaticDiff is now disabled by default for the KASPA family. Use it at your own risks.
                if(extraPoolConfig.EnableStaticDifficulty)
                    context.VarDiff = null; // disable vardiff

                context.SetDifficulty(staticDiff.Value);

                if(extraPoolConfig.EnableStaticDifficulty)
                    logger.Info(() => $"[{connection.ConnectionId}] Setting static difficulty of {staticDiff.Value}");
                else
                    logger.Warn(() => $"[{connection.ConnectionId}] Requesting static difficulty of {staticDiff.Value} (Request has been ignored and instead used as 'initial difficulty' for varDiff)");
            }

            var minerJobParams = CreateWorkerJob(connection);

            // send intial update
            await connection.NotifyAsync(KaspaStratumMethods.SetDifficulty, new object[] { context.Difficulty });
            await SendJob(connection, context, minerJobParams);
        }

        else
        {
            await connection.RespondErrorAsync(StratumError.UnauthorizedWorker, "Authorization failed", request.Id, context.IsAuthorized);

            if(clusterConfig?.Banning?.BanOnLoginFailure is null or true)
            {
                // issue short-time ban if unauthorized to prevent DDos on daemon (validateaddress RPC)
                logger.Info(() => $"[{connection.ConnectionId}] Banning unauthorized worker {minerName} for {loginFailureBanTimeout.TotalSeconds} sec");

                banManager.Ban(connection.RemoteEndpoint.Address, loginFailureBanTimeout);

                Disconnect(connection);
            }
        }
    }

    private object[] CreateWorkerJob(StratumConnection connection)
    {
        var context = connection.ContextAs<KaspaWorkerContext>();
        var maxActiveJobs = extraPoolConfig?.MaxActiveJobs ?? 8;
        var job = manager.GetJobForStratum();

        // update context
        lock(context)
        {
            context.AddJob(job, maxActiveJobs);
        }

        return job.GetJobParams();
    }

    protected virtual async Task OnSubmitAsync(StratumConnection connection, Timestamped<JsonRpcRequest> tsRequest, CancellationToken ct)
    {
        var request = tsRequest.Value;
        var context = connection.ContextAs<KaspaWorkerContext>();

        try
        {
            if(request.Id == null)
                throw new StratumException(StratumError.MinusOne, "missing request id");

            // check age of submission (aged submissions are usually caused by high server load)
            var requestAge = clock.Now - tsRequest.Timestamp.UtcDateTime;

            if(requestAge > maxShareAge)
            {
                logger.Warn(() => $"[{connection.ConnectionId}] Dropping stale share submission request (server overloaded?)");
                return;
            }

            // check worker state
            context.LastActivity = clock.Now;

            // validate worker
            if(!context.IsAuthorized)
                throw new StratumException(StratumError.UnauthorizedWorker, "Unauthorized worker");
            else if(!context.IsSubscribed)
                throw new StratumException(StratumError.NotSubscribed, "Not subscribed");

            var requestParams = request.ParamsAs<string[]>();

            // submit
            var share = await manager.SubmitShareAsync(connection, requestParams, ct);

            // Nicehash's stupid validator insists on "error" property present
            // in successful responses which is a violation of the JSON-RPC spec
            // [Respect the goddamn standards Nicehack :(]
            var response = new JsonRpcResponse<object>(true, request.Id);

            if(context.IsNicehash || manager.ValidateIsGoldShell(context.UserAgent))
            {
                response.Extra = new Dictionary<string, object>();
                response.Extra["error"] = null;
            }
            await connection.RespondAsync(response);

            // publish
            messageBus.SendMessage(share);

            // telemetry
            PublishTelemetry(TelemetryCategory.Share, clock.Now - tsRequest.Timestamp.UtcDateTime, true);

            logger.Info(() => $"[{connection.ConnectionId}] Share accepted: D={Math.Round(share.Difficulty * coin.ShareMultiplier, 3)}");

            // update pool stats
            if(share.IsBlockCandidate)
                poolStats.LastPoolBlockTime = clock.Now;

            // update client stats
            context.Stats.ValidShares++;

            await UpdateVarDiffAsync(connection, false, ct);
        }

        catch(StratumException ex)
        {
            // telemetry
            PublishTelemetry(TelemetryCategory.Share, clock.Now - tsRequest.Timestamp.UtcDateTime, false);

            // update client stats
            context.Stats.InvalidShares++;
            logger.Info(() => $"[{connection.ConnectionId}] Share rejected: {ex.Message} [{context.UserAgent}]");

            // banning
            ConsiderBan(connection, context, poolConfig.Banning);

            throw;
        }
    }

    protected virtual async Task OnNewJobAsync(object[] jobParams)
    {
        currentJobParams = jobParams;

        logger.Info(() => $"Broadcasting job {jobParams[0]}");

        await Guard(() => ForEachMinerAsync(async (connection, ct) =>
        {
            var context = connection.ContextAs<KaspaWorkerContext>();

            var minerJobParams = CreateWorkerJob(connection);

            // varDiff: if the client has a pending difficulty change, apply it now
            if(context.ApplyPendingDifficulty())
                await connection.NotifyAsync(KaspaStratumMethods.SetDifficulty, new object[] { context.Difficulty });

            await SendJob(connection, context, minerJobParams);
        }));
    }

    private async Task SendJob(StratumConnection connection, KaspaWorkerContext context, object[] jobParams)
    {
        object[] jobParamsActual;
        if(context.IsLargeJob)
        {
            jobParamsActual = new object[] {
                jobParams[0],
                jobParams[1],
            };
        }
        else
        {
            jobParamsActual = new object[] {
                jobParams[0],
                jobParams[2],
                jobParams[3],
            };
        }

        // send job
        await connection.NotifyAsync(KaspaStratumMethods.MiningNotify, jobParamsActual);
    }

    public override double HashrateFromShares(double shares, double interval)
    {
        var multiplier = coin.HashrateMultiplier;
        var result = shares * multiplier / interval;

        return result;
    }

    public override double ShareMultiplier => coin.ShareMultiplier;

    #region Overrides

    public override void Configure(PoolConfig pc, ClusterConfig cc)
    {
        coin = pc.Template.As<KaspaCoinTemplate>();
        extraPoolConfig = pc.Extra.SafeExtensionDataAs<KaspaPoolConfigExtra>();

        base.Configure(pc, cc);
    }

    protected override async Task SetupJobManager(CancellationToken ct)
    {
        var extraNonce1Size = extraPoolConfig?.ExtraNonce1Size ?? 2;

        manager = ctx.Resolve<KaspaJobManager>(
            new TypedParameter(typeof(IExtraNonceProvider), new KaspaExtraNonceProvider(poolConfig.Id, extraNonce1Size, clusterConfig.InstanceId)));

        manager.Configure(poolConfig, clusterConfig);

        await manager.StartAsync(ct);

        if(poolConfig.EnableInternalStratum == true)
        {
            disposables.Add(manager.Jobs
                .Select(job => Observable.FromAsync(() =>
                    Guard(()=> OnNewJobAsync(job),
                        ex=> logger.Debug(() => $"{nameof(OnNewJobAsync)}: {ex.Message}"))))
                .Concat()
                .Subscribe(_ => { }, ex =>
                {
                    logger.Debug(ex, nameof(OnNewJobAsync));
                }));

            // start with initial blocktemplate
            await manager.Jobs.Take(1).ToTask(ct);
        }

        else
        {
            // keep updating NetworkStats
            disposables.Add(manager.Jobs.Subscribe());
        }
    }

    protected override async Task InitStatsAsync(CancellationToken ct)
    {
        await base.InitStatsAsync(ct);

        blockchainStats = manager.BlockchainStats;
    }

    protected override WorkerContextBase CreateWorkerContext()
    {
        return new KaspaWorkerContext();
    }

    protected override async Task OnRequestAsync(StratumConnection connection,
        Timestamped<JsonRpcRequest> tsRequest, CancellationToken ct)
    {
        var request = tsRequest.Value;

        try
        {
            switch(request.Method)
            {
                case KaspaStratumMethods.Subscribe:
                    await OnSubscribeAsync(connection, tsRequest, ct);
                    break;
                
                case KaspaStratumMethods.ExtraNonceSubscribe:
                    var context = connection.ContextAs<KaspaWorkerContext>();
                    
                    var data = new object[]
                    {
                        context.ExtraNonce1,
                        KaspaConstants.ExtranoncePlaceHolderLength - manager.GetExtraNonce1Size(),
                    };
                    
                    await connection.NotifyAsync(KaspaStratumMethods.SetExtraNonce, data);
                    break;
                
                case KaspaStratumMethods.Authorize:
                    await OnAuthorizeAsync(connection, tsRequest, ct);
                    break;

                case KaspaStratumMethods.SubmitShare:
                    await OnSubmitAsync(connection, tsRequest, ct);
                    break;
                
                default:
                    logger.Debug(() => $"[{connection.ConnectionId}] Unsupported RPC request: {JsonConvert.SerializeObject(request, serializerSettings)}");

                    await connection.RespondErrorAsync(StratumError.Other, $"Unsupported request {request.Method}", request.Id);
                    break;
            }
        }

        catch(StratumException ex)
        {
            await connection.RespondErrorAsync(ex.Code, ex.Message, request.Id, false);
        }
    }

    protected override async Task<double?> GetNicehashStaticMinDiff(WorkerContextBase context, string coinName, string algoName)
    {
        var result = await base.GetNicehashStaticMinDiff(context, coinName, algoName);

        // adjust value to fit with our target value calculation
        if(result.HasValue)
            result = result.Value / uint.MaxValue;

        return result;
    }

    protected override async Task OnVarDiffUpdateAsync(StratumConnection connection, double newDiff, CancellationToken ct)
    {
        await base.OnVarDiffUpdateAsync(connection, newDiff, ct);

        var context = connection.ContextAs<KaspaWorkerContext>();

        if(context.ApplyPendingDifficulty())
        {
            var minerJobParams = CreateWorkerJob(connection);

            // send varDiff update
            await connection.NotifyAsync(KaspaStratumMethods.SetDifficulty, new object[] { context.Difficulty });
            await SendJob(connection, context, minerJobParams);
        }
    }

    #endregion // Overrides
}