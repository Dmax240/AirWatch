"""Discover actual Hashcat devices and prefer measured speed, then GeForce."""
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import subprocess

from .ai import APP_ROOT


@dataclass(frozen=True)
class Device:
    id: str
    name: str
    backend: str
    type: str

    @property
    def label(self):
        return f"{self.name} · {self.backend} · device {self.id}"


def recovery_environment():
    env = os.environ.copy()
    lib = APP_ROOT / "tools/nvidia/usr/lib/x86_64-linux-gnu/nvidia/current"
    version_file = Path("/proc/driver/nvidia/version")
    # The private runtime matches this machine's installed 550 driver. After a
    # driver upgrade, use the system runtime instead of loading mismatched libs.
    if ((lib / "libnvidia-opencl.so.1").exists() and version_file.exists()
            and "550.163.01" in version_file.read_text()
            and not Path("/etc/OpenCL/vendors/nvidia.icd").exists()):
        vendors = APP_ROOT / "tools/opencl-vendors"
        vendors.mkdir(exist_ok=True)
        for path in Path("/etc/OpenCL/vendors").glob("*.icd"):
            (vendors / path.name).write_text(path.read_text())
        (vendors / "nvidia.icd").write_text(str(lib / "libnvidia-opencl.so.1") + "\n")
        env["OCL_ICD_VENDORS"] = str(vendors)
        env["LD_LIBRARY_PATH"] = str(lib) + (":" + env["LD_LIBRARY_PATH"] if env.get("LD_LIBRARY_PATH") else "")
    return env


def parse_devices(text):
    devices = []
    backend, current = "Unknown", None
    for line in text.splitlines():
        stripped = line.strip()
        if re.match(r"^(CUDA|HIP|OpenCL|Metal) Info:", stripped):
            backend = stripped.split()[0]
            current = None
        if stripped.startswith("OpenCL Platform ID"):
            current = None
        match = re.search(r"Backend Device ID #0*(\d+)", line)
        if match:
            current = {"id": str(int(match.group(1))), "backend": backend,
                       "name": "", "type": "GPU" if backend in ("CUDA", "HIP", "Metal") else ""}
            devices.append(current)
        elif current:
            match = re.match(r"\s*(Name|Type)\.+:\s*(.+)", line)
            if match:
                current[match.group(1).lower()] = match.group(2).strip()
    return [Device(**d) for d in devices if d["name"] and "GPU" in d["type"]]


def discover():
    result = subprocess.run(["hashcat", "-I"], capture_output=True, text=True,
                            timeout=30, env=recovery_environment())
    output = result.stdout + result.stderr
    devices = parse_devices(output)
    if result.returncode and not devices:
        raise RuntimeError("Hashcat device detection failed. " + output[-1600:])
    return devices, output


def measured_speeds():
    try:
        data = json.loads((APP_ROOT / "gpu-benchmarks.json").read_text())
        return {name: float(speed) for name, speed in data.get("hashes_per_second", {}).items() if float(speed) > 0}
    except (OSError, ValueError, TypeError):
        return {}


def preferred_device(devices, speeds=None):
    if not devices:
        return None
    geforce = [d for d in devices if "geforce" in d.name.lower()]
    if not geforce:
        return None
    speeds = measured_speeds() if speeds is None else speeds
    if all(d.name in speeds for d in devices):
        return max(devices, key=lambda d: speeds[d.name])
    if geforce:
        return max(geforce, key=lambda d: speeds.get(d.name, 0))
    # The user's preferred GeForce must not silently turn into an Arc run.
    return None
