def enrich(iocs, client, cache):
    """Look each indicator up in the cache first, and only query the API on a miss."""
    results = []
    for ioc in iocs:
        kind, value = ioc["kind"], ioc["value"]
        cached = cache.get(kind, value)

        if cached is not None:
            result = {**cached, "cached": True}
        else:
            result = client.lookup(kind, value)
            cache.set(kind, value, result)
            cache.save()  # save after every lookup so an interrupted run keeps its progress
            result = {**result, "cached": False}

        results.append({**ioc, **result})
    return results
