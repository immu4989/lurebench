"""Check installed cache persistence outside the checkout with python -I -S.

Uses synthetic callbacks only; no optional libraries, providers, or network.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path


def check(root: Path) -> None:
    root = root.resolve(strict=True)
    checkout = Path(__file__).resolve().parents[1]
    if Path.cwd().resolve().is_relative_to(checkout) or root == checkout:
        raise ValueError("run against an installed wheel outside the checkout")
    if any(name == "lurebench" or name.startswith("lurebench.") for name in sys.modules):
        raise ValueError("fresh interpreter required")
    if not sys.flags.isolated or not sys.flags.no_site:
        raise ValueError("use python -I -S to disable ambient import paths and site packages")
    sys.path.insert(0, str(root))
    from lurebench import diskcache
    from lurebench.diskcache import CacheWriteError, JsonDiskCache
    from lurebench.generate.completion_cache import CompletionCache

    with tempfile.TemporaryDirectory(prefix="lure-cache-install-") as directory:
        path = Path(directory) / "cache.json"
        cache = JsonDiskCache(str(path), flush_every=0)
        cache.set("saved", "previous observation")
        cache.flush()
        previous = path.read_bytes()
        cache.set("invalid", {1: "first", "1": "second"})
        try:
            cache.flush()
        except CacheWriteError:
            pass
        else:
            raise ValueError("installed cache accepted ambiguous staged bytes")
        if path.read_bytes() != previous or cache._pending != 1:
            raise ValueError("failed persistence lost previous file or pending work")
        cache.set("invalid", "corrected")
        cache.flush()
        if JsonDiskCache(str(path), read_only=True).get("invalid") != "corrected":
            raise ValueError("installed cache did not survive restart")

        completion_path = Path(directory) / "completions.json"
        completion_cache = CompletionCache(str(completion_path), flush_every=1, max_new_calls=1)
        calls = []

        def provider(system, user):
            calls.append(1)
            return "one synthetic completion"

        complete = completion_cache.wrap(provider, model="synthetic")
        original_limit = diskcache.MAX_CACHE_BYTES
        try:
            diskcache.MAX_CACHE_BYTES = 1
            try:
                complete("system", "input")
            except CacheWriteError:
                pass
            else:
                raise ValueError("installed cache ignored its byte limit")
            if complete("system", "input") != "one synthetic completion" or calls != [1]:
                raise ValueError("persistence failure repeated the callback")
        finally:
            diskcache.MAX_CACHE_BYTES = original_limit
        completion_cache.flush()
        replay = CompletionCache(str(completion_path), cache_only=True).wrap(provider, model="synthetic")
        if replay("system", "input") != "one synthetic completion" or calls != [1]:
            raise ValueError("restart replay repeated the callback")
        if list(Path(directory).glob(".lurecache-*.tmp")):
            raise ValueError("cache temporary files leaked")
    for name, module in tuple(sys.modules.items()):
        if name == "lurebench" or name.startswith("lurebench."):
            location = getattr(module, "__file__", None)
            if not location or not Path(location).resolve().is_relative_to(root):
                raise ValueError("producer import escaped installed root")
    print("Verified installed cache preservation, persistence retry, and provider-free restart replay")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installed-root", type=Path, required=True)
    check(parser.parse_args().installed_root)
