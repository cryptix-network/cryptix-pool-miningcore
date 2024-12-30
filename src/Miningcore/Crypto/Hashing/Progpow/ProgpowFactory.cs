using System.Collections.Concurrent;
using Autofac;

namespace Miningcore.Crypto.Hashing.Progpow;

public static class ProgpowFactory
{
    private static readonly ConcurrentDictionary<string, IProgpowLight> cacheFull = new();

    public static IProgpowLight GetProgpow(string symbol, IComponentContext ctx, string name)
    {
        if(string.IsNullOrEmpty(symbol) || string.IsNullOrEmpty(name))
            return null;

        // check cache
        if(cacheFull.TryGetValue(symbol, out var result))
            return result;

        result = ctx.ResolveNamed<IProgpowLight>(name);

        cacheFull.TryAdd(symbol, result);

        return result;
    }
}