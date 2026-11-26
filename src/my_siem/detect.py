from collections import defaultdict, deque


class RateDetector:
    """Flag a key (e.g. a source IP) that hits `threshold` times within `window` seconds."""

    def __init__(self, threshold: int, window: float) -> None:
        self.threshold = threshold
        self.window = window
        self._hits: defaultdict[str, deque[float]] = defaultdict(deque)

    def hit(self, key: str, now: float) -> bool:
        hits = self._hits[key]
        hits.append(now)
        while hits and hits[0] <= now - self.window:
            hits.popleft()
        if len(hits) >= self.threshold:
            # Start counting afresh so an ongoing attack alerts once per burst.
            hits.clear()
            return True
        return False
