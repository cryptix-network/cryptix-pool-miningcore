using Autofac;
using Microsoft.AspNetCore.Mvc;
using Miningcore.Extensions;
using Miningcore.Mining;
using Miningcore.Persistence.Repositories;
using Miningcore.Util;
using System.Collections.Concurrent;
using System.Net;
using NLog;
using NLog.Targets;

namespace Miningcore.Api.Controllers;

[Route("api/admin")]
[ApiController]
public class AdminApiController : ApiControllerBase
{
    public AdminApiController(IComponentContext ctx) : base(ctx)
    {
        gcStats = ctx.Resolve<Responses.AdminGcStats>();
        minerRepo = ctx.Resolve<IMinerRepository>();
        pools = ctx.Resolve<ConcurrentDictionary<string, IMiningPool>>();
        paymentsRepo = ctx.Resolve<IPaymentRepository>();
        balanceRepo = ctx.Resolve<IBalanceRepository>();
    }

    private readonly IPaymentRepository paymentsRepo;
    private readonly IBalanceRepository balanceRepo;
    private readonly IMinerRepository minerRepo;
    private readonly ConcurrentDictionary<string, IMiningPool> pools;

    private readonly Responses.AdminGcStats gcStats;

    private static readonly ILogger logger = LogManager.GetCurrentClassLogger();

    #region Actions

    [HttpGet("logging/level/{level}")]
    public ActionResult<string> SetLoggingLevel(string level)
    {
        if (string.IsNullOrEmpty(level))
            throw new ApiException("Invalid logging level", HttpStatusCode.BadRequest);

        var logLevel = LogLevel.FromString(level);

        if (logLevel == null)
            throw new ApiException("Invalid logging level", HttpStatusCode.BadRequest);

        logger.Error("Admin update Logging Level this is Error");
        logger.Trace("Admin update Logging Level this is Trace");

        foreach (var rule in LogManager.Configuration.LoggingRules)
        {
            rule.EnableLoggingForLevel(logLevel);
            rule.SetLoggingLevels(logLevel, LogLevel.Fatal); // set minimum logging level
        }

        Target target = LogManager.Configuration.FindTargetByName("console");

        if (target != null)
        {
            var loggingConfig = LogManager.Configuration;

            loggingConfig.AddRule(logLevel, LogLevel.Fatal, target);

            LogManager.Configuration = loggingConfig;
        }

        LogManager.ReconfigExistingLoggers();

        logger.Error("Admin update Logging Level this is Error AFTER");
        logger.Trace("Admin update Logging Level this is Trace AFTER");

        logger.Info($"Logging level set to {level}");
        return "Ok";
    }

    [HttpGet("payment/processing/enable")]
    public ActionResult<string> EnablePoolsPaymentProcessing()
    {
        var poolIdsUpdated = new List<string>();
        foreach(var pool in pools.Values)
        {
            if(!pool.Config.Enabled)
                continue;

            poolIdsUpdated.Add(pool.Config.Id);
            pool.Config.PaymentProcessing.Enabled = true;
        }

        // Join the poolIdsUpdated into CSV string
        var poolIdsCsv = String.Join(",", poolIdsUpdated);
        logger.Info(()=> $"Enabled payment processing for pool {poolIdsCsv}");

        return poolIdsCsv;
    }

    [HttpGet("payment/processing/disable")]
    public ActionResult<string> DisablePoolsPaymentProcessing()
    {
        var poolIdsUpdated = new List<string>();
        foreach(var pool in pools.Values)
        {
            if(!pool.Config.Enabled)
                continue;

            poolIdsUpdated.Add(pool.Config.Id);
            pool.Config.PaymentProcessing.Enabled = false;
        }

        // Join the poolIdsUpdated into CSV string
        var poolIdsCsv = String.Join(",", poolIdsUpdated);
        logger.Info(()=> $"Disabled payment processing for pool {poolIdsCsv}");

        return poolIdsCsv;
    }

    [HttpGet("payment/processing/{poolId}/enable")]
    public ActionResult<string> EnablePoolPaymentProcessing(string poolId)
    {
        if (string.IsNullOrEmpty(poolId))
            throw new ApiException("Missing pool ID", HttpStatusCode.BadRequest);

        pools.TryGetValue(poolId, out var poolInstance);
        if(poolInstance == null)
            return "-1";

        poolInstance.Config.PaymentProcessing.Enabled = true;
        logger.Info(()=> $"Enabled payment processing for pool {poolId}");
        return "Ok";
    }

    [HttpGet("payment/processing/{poolId}/disable")]
    public ActionResult<string> DisablePoolPaymentProcessing(string poolId)
    {
        if (string.IsNullOrEmpty(poolId))
            throw new ApiException("Missing pool ID", HttpStatusCode.BadRequest);

        pools.TryGetValue(poolId, out var poolInstance);
        if(poolInstance == null)
            return "-1";

        poolInstance.Config.PaymentProcessing.Enabled = false;
        logger.Info(()=> $"Disabled payment processing for pool {poolId}");
        return "Ok";
    }

    [HttpGet("stats/gc")]
    public ActionResult<Responses.AdminGcStats> GetGcStats()
    {
        gcStats.GcGen0 = GC.CollectionCount(0);
        gcStats.GcGen1 = GC.CollectionCount(1);
        gcStats.GcGen2 = GC.CollectionCount(2);
        gcStats.MemAllocated = FormatUtil.FormatCapacity(GC.GetTotalMemory(false));

        return gcStats;
    }

    [HttpPost("forcegc")]
    public ActionResult<string> ForceGc()
    {
        GC.Collect(2, GCCollectionMode.Forced);
        return "Ok";
    }

    [HttpGet("pools/{poolId}/miners/{address}/getbalance")]
    public async Task<decimal> GetMinerBalanceAsync(string poolId, string address)
    {
        return await cf.Run(con => balanceRepo.GetBalanceAsync(con, poolId, address));
    }

    [HttpGet("pools/{poolId}/miners/{address}/settings")]
    public async Task<Responses.MinerSettings> GetMinerSettingsAsync(string poolId, string address)
    {
        var pool = GetPool(poolId);

        if(string.IsNullOrEmpty(address))
            throw new ApiException("Invalid or missing miner address", HttpStatusCode.NotFound);

        var result = await cf.Run(con=> minerRepo.GetSettingsAsync(con, null, pool.Id, address));

        if(result == null)
            throw new ApiException("No settings found", HttpStatusCode.NotFound);

        return mapper.Map<Responses.MinerSettings>(result);
    }

    [HttpPost("pools/{poolId}/miners/{address}/settings")]
    public async Task<Responses.MinerSettings> SetMinerSettingsAsync(string poolId, string address,
        [FromBody] Responses.MinerSettings settings)
    {
        var pool = GetPool(poolId);

        if(string.IsNullOrEmpty(address))
            throw new ApiException("Invalid or missing miner address", HttpStatusCode.NotFound);

        if(settings == null)
            throw new ApiException("Invalid or missing settings", HttpStatusCode.BadRequest);

        // map settings
        var mapped = mapper.Map<Persistence.Model.MinerSettings>(settings);

        // clamp limit
        if(pool.PaymentProcessing != null)
            mapped.PaymentThreshold = Math.Max(mapped.PaymentThreshold, pool.PaymentProcessing.MinimumPayment);

        mapped.PoolId = pool.Id;
        mapped.Address = address;

        var result = await cf.RunTx(async (con, tx) =>
        {
            await minerRepo.UpdateSettingsAsync(con, tx, mapped);

            return await minerRepo.GetSettingsAsync(con, tx, mapped.PoolId, mapped.Address);
        });

        logger.Info(()=> $"Updated settings for pool {pool.Id}, miner {address}");

        return mapper.Map<Responses.MinerSettings>(result);
    }

    #endregion // Actions
}
