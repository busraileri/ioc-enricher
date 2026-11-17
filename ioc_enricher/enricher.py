def enrich(iocs, client, cache):
    """Göstergeleri önce önbellekte arar, yoksa API'ye sorar."""
    results = []
    for ioc in iocs:
        kind, value = ioc["kind"], ioc["value"]
        cached = cache.get(kind, value)

        if cached is not None:
            result = {**cached, "cached": True}
        else:
            result = client.lookup(kind, value)
            cache.set(kind, value, result)
            cache.save()  # her sorgudan sonra yaz: yarıda kesilirse ilerleme kaybolmaz
            result = {**result, "cached": False}

        results.append({**ioc, **result})
    return results
