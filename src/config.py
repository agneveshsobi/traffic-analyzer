import os
import yaml

DEFAULTS = {
    "port_scan": {"threshold": 20, "window": 10},
    "dns_tunneling": {"min_label_len": 25, "entropy_limit": 3.5, "min_hits": 5},
    "beaconing": {"min_connections": 8, "max_variation": 0.2, "min_interval": 5},
}

PATH = os.path.join(os.path.dirname(__file__), "..", "config.yaml")


def load_config():
    cfg = {k: dict(v) for k, v in DEFAULTS.items()}
    if os.path.exists(PATH):
        with open(PATH) as f:
            user = yaml.safe_load(f) or {}
        for section, values in user.items():
            if section in cfg and isinstance(values, dict):
                cfg[section].update(values)
    return cfg
