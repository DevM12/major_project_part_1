import statistics


class ZScoreDetector:
    def __init__(self, events, threshold=3):
        requests = [e["requests_per_minute"] for e in events]
        failures = [e["failed_logins"] for e in events]
        self.mean = [statistics.mean(requests), statistics.mean(failures)]
        self.std = [statistics.pstdev(requests) or 1, statistics.pstdev(failures) or 1]
        self.threshold = threshold

    def check(self, requests_per_minute, failed_logins):
        z1 = abs((requests_per_minute - self.mean[0]) / self.std[0])
        z2 = abs((failed_logins - self.mean[1]) / self.std[1])
        z = round(max(z1, z2), 2)
        return z, z > self.threshold
