"""Small byte token bucket for bulk traffic; priority traffic bypasses it."""
import math
import time


class BulkPacer:
    def __init__(self, bytes_per_second, burst_bytes, *, clock=time.perf_counter):
        if not math.isfinite(bytes_per_second) or bytes_per_second <= 0:
            raise ValueError("bulk byte rate must be finite and positive")
        if type(burst_bytes) is not int or burst_bytes <= 0:
            raise ValueError("bulk burst must be a positive number of bytes")
        self.rate = bytes_per_second
        self.capacity = burst_bytes
        self.tokens = float(burst_bytes)
        self.clock = clock
        self.last = clock()

    def reserve(self, size):
        if type(size) is not int or size <= 0:
            raise ValueError("packet size must be positive")
        now = self.clock()
        self.tokens = min(self.capacity, self.tokens + max(0, now - self.last) * self.rate)
        self.last = now
        self.tokens -= size
        return max(0.0, -self.tokens / self.rate)
