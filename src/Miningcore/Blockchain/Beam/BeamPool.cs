using System.Globalization;
using System.Numerics;
using System.Reactive;
using System.Reactive.Linq;
using System.Reactive.Threading.Tasks;
using Autofac;
using AutoMapper;
using Microsoft.IO;
using Miningcore.Blockchain.Beam.StratumRequests;
using Miningcore.Blockchain.Beam.StratumResponses;
using Miningcore.Blockchain.Beam.Configuration;
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

namespace Miningcore.Blockchain.Beam;

[CoinFamily(CoinFamily.Beam)]
public class BeamPool : PoolBase
{
    public BeamPool(IComponentContext ctx,
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

    protected BeamJobManager manager;
    private BeamCoinTemplate coin;
    
    private async Task OnLoginAsync(StratumConnection connection, Timestamped<JsonRpcRequest> tsRequest, CancellationToken ct)
    {
        // Beam stratum API: https://github.com/BeamMW/beam/wiki/Beam-mining-protocol-API-(Stratum)
        var request = JsonConvert.DeserializeObject<BeamLoginRequest>(JsonConvert.SerializeObject(tsRequest.Value));
        
        if(request.Login == null)
            throw new StratumException(StratumError.MinusOne, "Login failed: missing 'api_key'");
        
        var context = connection.ContextAs<BeamWorkerContext>();
        var workerValue = request?.Login;
        var password = !string.IsNullOrEmpty(request?.Password) ? request.Password : null;
        var passParts = password?.Split(PasswordControlVarsSeparator);

        context.UserAgent = request?.UserAgent;

        // extract worker/miner
        var split = workerValue?.Split('.');
        var minerName = split?.FirstOrDefault()?.Trim();
        var workerName = split?.Skip(1).FirstOrDefault()?.Trim() ?? string.Empty;

        // assumes that workerName is an address
        context.IsAuthorized = await manager.ValidateAddressAsync(minerName, ct);
        context.Miner = minerName;
        context.Worker = workerName;

        if(context.IsAuthorized)
        {
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
                context.VarDiff = null; // disable vardiff
                context.SetDifficulty(staticDiff.Value);

                logger.Info(() => $"[{connection.ConnectionId}] Setting static difficulty of {staticDiff.Value}");
            }
            
            // setup worker context
            context.IsSubscribed = true;
            
            // response
            var loginResponse = new BeamLoginResponse {
                Code = BeamConstants.BeamRpcLoginSuccess,
                Description = "Login successful",
                Nonceprefix = manager.GetSubscriberData(connection),
                Forkheight = manager?.Forkheight,
                Forkheight2 = manager?.Forkheight2
            };
            
            // respond
            await connection.NotifyAsync(loginResponse);
            
            // log association
            logger.Info(() => $"[{connection.ConnectionId}] Authorized worker {workerValue}");
            
            var currentJobParams = manager.GetJobParamsForStratum();
            logger.Info(() => $"Broadcasting job {currentJobParams[0]}");
            
            // response
            var jobResponse = new BeamJobResponse {
                Id = (string) currentJobParams[0],
                Height = (ulong) currentJobParams[1],
                Difficulty = BeamUtils.PackedDifficulty(connection.Context.Difficulty),
                Input = (string) currentJobParams[4],
                Nonceprefix = context.ExtraNonce1
            };
            
            // respond
            await connection.NotifyAsync(jobResponse);
        }

        else
        {   
            // response
            var loginFailureResponse = new BeamLoginResponse {
                Code = BeamConstants.BeamRpcLoginFailure,
                Description = "Login failed"
            };
            
            // respond
            await connection.NotifyAsync(loginFailureResponse);

            if(clusterConfig?.Banning?.BanOnLoginFailure is null or true)
            {
                // issue short-time ban if unauthorized to prevent DDos on daemon (validateaddress RPC)
                logger.Info(() => $"[{connection.ConnectionId}] Banning unauthorized worker {minerName} for {loginFailureBanTimeout.TotalSeconds} sec");

                banManager.Ban(connection.RemoteEndpoint.Address, loginFailureBanTimeout);

                Disconnect(connection);
            }
        }
    }

    protected virtual async Task OnSubmitAsync(StratumConnection connection, Timestamped<JsonRpcRequest> tsRequest, CancellationToken ct)
    {
        // Beam stratum API: https://github.com/BeamMW/beam/wiki/Beam-mining-protocol-API-(Stratum)
        var request = JsonConvert.DeserializeObject<BeamSubmitRequest>(JsonConvert.SerializeObject(tsRequest.Value));
        var context = connection.ContextAs<BeamWorkerContext>();

        try
        {
            if(request?.Id == null)
                throw new StratumException(StratumError.MinusOne, "missing id");

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
            {
                // response
                var submitIsAuthorizedResponse = new BeamSubmitResponse {
                    Id = request?.Id,
                    Code = BeamConstants.BeamRpcUnauthorizedWorker,
                    Description = "Unauthorized worker, please login first",
                };

                // respond
                await connection.NotifyAsync(submitIsAuthorizedResponse);
                throw new StratumException(StratumError.UnauthorizedWorker, "Unauthorized worker, please login first");
            }
            
            else if(!context.IsSubscribed)
            {
                // response
                var submitIsSubscribedResponse = new BeamSubmitResponse {
                    Id = request?.Id,
                    Code = BeamConstants.BeamRpcNotSubscribed,
                    Description = "Worker not subscribed"
                };

                // respond
                await connection.NotifyAsync(submitIsSubscribedResponse);
                throw new StratumException(StratumError.NotSubscribed, "Worker not subscribed");
            }
            
            else
            {
                // submit
                var (share, stratumError) = manager.SubmitShare(connection, request?.Id, request?.Nonce, request?.Output, ct);
                
                if (stratumError == BeamConstants.BeamRpcInvalidShare)
                {
                    // response
                    var submitInvalidShareResponse = new BeamSubmitResponse {
                        Id = request?.Id,
                        Code = BeamConstants.BeamRpcInvalidShare,
                        Description = "Invalid Share"
                    };

                    // respond
                    await connection.NotifyAsync(submitInvalidShareResponse);
                    throw new StratumException(StratumError.Other, "Invalid Share");
                }
                
                else if (stratumError == BeamConstants.BeamRpcLowDifficultyShare)
                {
                    // response
                    var submitLowDifficultyShareResponse = new BeamSubmitResponse {
                        Id = request?.Id,
                        Code = BeamConstants.BeamRpcLowDifficultyShare,
                        Description = $"low difficulty share ({share.Difficulty})"
                    };

                    // respond
                    await connection.NotifyAsync(submitLowDifficultyShareResponse);
                    throw new StratumException(StratumError.Other, $"low difficulty share ({share.Difficulty})");
                }
                
                else if (stratumError == BeamConstants.BeamRpcShareBadNonce)
                {
                    // response
                    var submitShareBadNonceResponse = new BeamSubmitResponse {
                        Id = request?.Id,
                        Code = BeamConstants.BeamRpcShareBadNonce,
                        Description = $"incorrect size of nonce ({request?.Nonce.Length}), expected: {BeamConstants.NonceSize}"
                    };

                    // respond
                    await connection.NotifyAsync(submitShareBadNonceResponse);
                    throw new StratumException(StratumError.Other, $"incorrect size of nonce ({request?.Nonce.Length}), expected: {BeamConstants.NonceSize}");
                }
                
                else if (stratumError == BeamConstants.BeamRpcShareBadSolution)
                {
                    // response
                    var submitShareBadSolutionResponse = new BeamSubmitResponse {
                        Id = request?.Id,
                        Code = BeamConstants.BeamRpcShareBadSolution,
                        Description = $"incorrect size of solution ({request?.Output.Length}), expected: {BeamConstants.SolutionSize}"
                    };

                    // respond
                    await connection.NotifyAsync(submitShareBadSolutionResponse);
                    throw new StratumException(StratumError.Other, $"incorrect size of solution ({request?.Output.Length}), expected: {BeamConstants.SolutionSize}");
                }
                
                else if (stratumError == BeamConstants.BeamRpcDuplicateShare)
                {
                    // response
                    var submitDuplicateShareResponse = new BeamSubmitResponse {
                        Id = request?.Id,
                        Code = BeamConstants.BeamRpcDuplicateShare,
                        Description = "duplicate share"
                    };

                    // respond
                    await connection.NotifyAsync(submitDuplicateShareResponse);
                    throw new StratumException(StratumError.Other, "duplicate share");
                }
                
                else if (stratumError == BeamConstants.BeamRpcJobNotFound)
                {
                    // response
                    var submitJobNotFoundResponse = new BeamSubmitResponse {
                        Id = request?.Id,
                        Code = BeamConstants.BeamRpcJobNotFound,
                        Description = "job not found"
                    };

                    // respond
                    await connection.NotifyAsync(submitJobNotFoundResponse);
                    throw new StratumException(StratumError.Other, "job not found");
                }
                
                else
                {
                    // response
                    var shareAcceptedResponse = new BeamSubmitResponse {
                        Id = request?.Id,
                        Code = BeamConstants.BeamRpcShareAccepted,
                        Description = "accepted"
                    };

                    await connection.NotifyAsync(shareAcceptedResponse);

                    // publish
                    messageBus.SendMessage(share);

                    // telemetry
                    PublishTelemetry(TelemetryCategory.Share, clock.Now - tsRequest.Timestamp.UtcDateTime, true);

                    logger.Info(() => $"[{connection.ConnectionId}] Share accepted: D={Math.Round(share.Difficulty, 3)}");

                    // update pool stats
                    if(share.IsBlockCandidate)
                        poolStats.LastPoolBlockTime = clock.Now;

                    // update client stats
                    context.Stats.ValidShares++;

                    await UpdateVarDiffAsync(connection, false, ct);
                }
            }
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

    protected async Task OnNewJobAsync(object[] jobParams)
    {
        var currentJobParams = jobParams;

        logger.Info(() => $"Broadcasting job {currentJobParams[0]}");

        await Guard(() => ForEachMinerAsync(async (connection, ct) =>
        {
            var context = connection.ContextAs<BeamWorkerContext>();
            
            // response
            var jobResponse = new BeamJobResponse {
                Id = (string) currentJobParams[0],
                Height = (ulong) currentJobParams[1],
                Difficulty = BeamUtils.PackedDifficulty(context.Difficulty),
                Input = (string) currentJobParams[4],
                Nonceprefix = context.ExtraNonce1
            };
            
            // respond
            await connection.NotifyAsync(jobResponse);
        }));
    }
    
    #region Overrides
    
    public override void Configure(PoolConfig pc, ClusterConfig cc)
    {
        coin = pc.Template.As<BeamCoinTemplate>();

        base.Configure(pc, cc);
    }

    protected override async Task SetupJobManager(CancellationToken ct)
    {
        manager = ctx.Resolve<BeamJobManager>(
            new TypedParameter(typeof(IExtraNonceProvider), new BeamExtraNonceProvider(poolConfig.Id, clusterConfig.InstanceId)));

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
    
    protected override async Task OnRequestAsync(StratumConnection connection,
        Timestamped<JsonRpcRequest> tsRequest, CancellationToken ct)
    {
        var request = tsRequest.Value;

        try
        {
            switch(request.Method)
            {
                case BeamStratumMethods.Login:
                    await OnLoginAsync(connection, tsRequest, ct);
                    break;

                case BeamStratumMethods.Submit:
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

    public override double HashrateFromShares(double shares, double interval)
    {
        var result = shares / interval;
        return result;
    }

    public override double ShareMultiplier => 1;
    
    protected override async Task OnVarDiffUpdateAsync(StratumConnection connection, double newDiff, CancellationToken ct)
    {
        await base.OnVarDiffUpdateAsync(connection, newDiff, ct);

        if(connection.Context.ApplyPendingDifficulty())
        {
            var currentJobParams = manager.GetJobParamsForStratum();
            var context = connection.ContextAs<BeamWorkerContext>();
            
            // response
            var jobResponse = new BeamJobResponse {
                Id = (string) currentJobParams[0],
                Height = (ulong) currentJobParams[1],
                Difficulty = BeamUtils.PackedDifficulty(context.Difficulty),
                Input = (string) currentJobParams[4],
                Nonceprefix = context.ExtraNonce1
            };
            
            // respond
            await connection.NotifyAsync(jobResponse);
        }
    }    

    protected override WorkerContextBase CreateWorkerContext()
    {
        return new BeamWorkerContext();
    }
    
    #endregion // Overrides
}