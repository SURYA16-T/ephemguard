"""Cross-platform system information collector."""
import os
import sys
import platform
import subprocess
import time

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


def get_system_info() -> dict:
    """Collect basic system information."""
    info = {
        "os": sys.platform,
        "platform": platform.platform(),
        "processor": platform.processor(),
        "architecture": platform.machine(),
        "hostname": platform.node(),
        "python_version": platform.python_version(),
        "timestamp": time.time(),
        "has_psutil": HAS_PSUTIL
    }
    
    if HAS_PSUTIL:
        # CPU
        info["cpu"] = {
            "physical_cores": psutil.cpu_count(logical=False),
            "total_cores": psutil.cpu_count(logical=True),
            "usage_percent": psutil.cpu_percent(interval=0.1)
        }
        
        # Memory
        mem = psutil.virtual_memory()
        info["memory"] = {
            "total_bytes": mem.total,
            "available_bytes": mem.available,
            "used_bytes": mem.used,
            "usage_percent": mem.percent
        }
        
        # Disk
        disk = psutil.disk_usage('/')
        info["disk"] = {
            "total_bytes": disk.total,
            "used_bytes": disk.used,
            "free_bytes": disk.free,
            "usage_percent": disk.percent
        }
        
        # Process summary
        info["processes"] = len(psutil.pids())
        
        # Network stats
        net_io = psutil.net_io_counters()
        info["network"] = {
            "bytes_sent": net_io.bytes_sent,
            "bytes_recv": net_io.bytes_recv
        }
    
    return info
