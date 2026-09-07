class EventNormalizer:

    def normalize(self, raw_log: dict):

        return {
            "timestamp": raw_log.get("timestamp"),
            "hostname": raw_log.get("hostname"),
            "source_ip": raw_log.get("src_ip"),
            "destination_ip": raw_log.get("dst_ip"),
            "event_type": raw_log.get("event"),
            "severity": raw_log.get("severity")
        }