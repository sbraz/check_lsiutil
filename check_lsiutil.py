#!/usr/bin/env python3
"""Nagios-like plugin to check LSI controllers"""

import argparse
import hashlib
import json
import logging
import pathlib
import pickle
import re
import subprocess

import nagiosplugin  # type: ignore

logger = logging.getLogger("nagiosplugin")

ERROR_COUNTERS = (
    "Invalid DWord Count",
    "Running Disparity Error Count",
    "Loss of DWord Synch Count",
    "Phy Reset Problem Count",
)
STATE_FILE_PATH = "/var/tmp"


def get_command_output(command):
    try:
        proc = subprocess.run(
            command,
            check=True,
            text=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as exc:
        raise nagiosplugin.CheckError(
            f"command {command} exited with status {exc.returncode}: {exc.stderr!r}"
        )
    logger.debug("Output from %s: %s", " ".join(command), proc.stdout)
    return proc.stdout


def sas_address_to_serial(parent_pci_device_path):
    out = get_command_output(["lsblk", "-dJ", "-o", "TYPE,KNAME,SERIAL"])
    data = json.loads(out)
    res = {}
    for device in data["blockdevices"]:
        if device["type"] != "disk" or device["serial"] is None:
            continue
        disk_path = pathlib.Path("/sys/block") / device["kname"] / "device"
        # Skip the disk if is not connected to the parent PCI device (the MPT port)
        # Emulate Python 3.9's "is_relative_to" function
        try:
            disk_path.resolve().relative_to(parent_pci_device_path.resolve())
        except ValueError:
            continue
        with (disk_path / "sas_address").open() as f:
            sas_address = int(f.read(), 16)
        # Sanitize serials to make perfdata processing easier
        res[sas_address] = device["serial"].replace("_", "-")
    return res


class LSIUtil(nagiosplugin.Resource):
    def __init__(self, args, args_hash):
        self.args = args
        self.args_hash = args_hash
        self.metrics = {}

    @classmethod
    def _list_ports(cls):
        out = get_command_output(["sudo", "-n", "lsiutil", "0"])
        ports = re.findall(r"^     Port Name.*\n^\s*(\d+)\.", out, flags=re.M)
        if not ports:
            raise nagiosplugin.CheckError("Could not find any MPT port")
        return ports

    @classmethod
    def _parse_devices(cls, port, command_output):
        # Find the PCI device associated to this port
        pci_info = re.search(r"^Seg/Bus/Dev/Fun.*\n((\s*\d+){4})", command_output, flags=re.M)
        pci_address_parts = (int(e) for e in pci_info.group(1).split())
        # pylint: disable-next=consider-using-f-string
        formatted_pci_address = "{:04x}:{:02x}:{:02x}.{:01x}".format(*pci_address_parts)
        pci_device_path = pathlib.Path("/sys/bus/pci/devices") / formatted_pci_address
        sas_address_to_serial_map = sas_address_to_serial(pci_device_path)
        # List devices connected to this port
        device_table = re.search(r"^ B___T.*?^$", command_output, flags=re.M | re.S)
        if not device_table:
            raise nagiosplugin.CheckError(f"Could not find any device on MPT port {port}")
        devices = {}
        for line in device_table.group(0).splitlines()[1:]:
            phynum = line[28:31].strip()
            if not phynum:
                continue
            phynum = int(phynum)
            address = int(line[8:25], 16)
            try:
                devices[phynum] = {"serial": sas_address_to_serial_map[address]}
            except KeyError:
                raise nagiosplugin.CheckError(
                    f"Could not determine block device associated with SAS address 0x{address:x}"
                ) from None
        if not devices:
            raise nagiosplugin.CheckError(f"Could not find any device on MPT port {port}")
        return devices

    @classmethod
    def _parse_phy_counters(cls, port, command_output):
        phy_counters_table = re.search(
            r"^Diagnostics menu,.*12.*?^Diagnostics menu,", command_output, flags=re.M | re.S
        )
        if not phy_counters_table:
            raise nagiosplugin.CheckError(
                f"Could not find PHY counter information for MPT port {port}"
            )
        phy_counters = {}
        phy_info = re.findall(
            r"^Adapter Phy \d+:.*?^$", phy_counters_table.group(0), flags=re.M | re.S
        )
        for counter_info in phy_info:
            phynum = int(re.search(r"^Adapter Phy (\d+):", counter_info).group(1))
            # Initialize all counters at zero because lsiutil doesn't display them for
            # physical ports that do not have errors.
            phy_counters[phynum] = {e: 0 for e in ERROR_COUNTERS}
            for counter_name in ERROR_COUNTERS:
                match = re.search(rf"^\s*{counter_name}\s+([\d,]+)", counter_info, flags=re.M)
                if match:
                    # Counters use commas as thousands separators
                    phy_counters[phynum][counter_name] = int(match.group(1).replace(",", ""))
        return phy_counters

    def _probe_port(self, port):
        command_output = get_command_output(
            # 69 = Show board manufacturing information
            # 16 = Display attached devices
            # 20 + 12 = Diagnostics + Display phy counters
            ["sudo", "-n", "lsiutil", "-p", port, "-a", "69,16,20,12,0,0"]
        )
        devices = self._parse_devices(port, command_output)
        for phynum, info in devices.items():
            yield nagiosplugin.Metric(
                name=f"{info['serial']}_phynum", value=phynum, context="scalar"
            )
        phy_counters = self._parse_phy_counters(port, command_output)
        if not phy_counters:
            raise nagiosplugin.CheckError(
                f"Could not find PHY counter information for MPT port {port}"
            )
        for phynum, info in devices.items():
            # Update devices with info for each physical port
            info.update(phy_counters[phynum])
            serial = info["serial"]
            if serial not in self.metrics:
                self.metrics[serial] = {}
            for counter_name in ERROR_COUNTERS:
                sanitized_counter_name = counter_name.lower().replace(" ", "_")
                if sanitized_counter_name not in self.metrics[serial]:
                    self.metrics[serial][sanitized_counter_name] = []
                values = self.metrics[serial][sanitized_counter_name]
                values.append(info[counter_name])
                if len(values) > (self.args.max_attempts + 1):
                    values.pop(0)
                yield nagiosplugin.Metric(
                    name=sanitized_counter_name,
                    value={"values": values, "serial": serial, "phynum": phynum},
                    context="counter",
                )

    def _save_cookie(self, state_file):
        with nagiosplugin.Cookie(str(state_file)) as cookie:
            cookie["metrics"] = self.metrics

    def _load_cookie(self, state_file):
        with nagiosplugin.Cookie(str(state_file)) as cookie:
            try:
                self.metrics = cookie["metrics"]
                logger.debug("Loaded old metrics from %s", state_file)
            except KeyError:
                yield nagiosplugin.Metric(
                    name="Warn",
                    value={"message": f"no data in state file {state_file}, first run?"},
                    context="metadata",
                )

    def probe(self):
        state_file = pathlib.Path(STATE_FILE_PATH) / f".check_lsiutil_{self.args_hash}"
        yield from self._load_cookie(state_file)
        ports = self._list_ports()
        yield nagiosplugin.Metric(
            name="Ok",
            value={"message": f"found {len(ports)} MPT port{'' if len(ports) == 1 else 's'}"},
            context="metadata",
        )
        for port in ports:
            yield from self._probe_port(port)
        self._save_cookie(state_file)


class LSIUtilSummary(nagiosplugin.Summary):
    def ok(self, results):
        return f"{results[0]} - no errors detected"

    def verbose(self, results):
        messages = []
        for result in results:
            if result.context.name == "counter":
                messages.append(
                    f"{result.metric.value['serial']} at port {result.metric.value['phynum']}: "
                    f"{result.metric.name}: {result.metric.value['values']}"
                )
            elif result.context.name == "metadata":
                messages.append(result.hint)
        return "\n".join(messages)

    def problem(self, results):
        messages = []
        # OK result first, then worst
        for result in sorted(
            results,
            key=lambda x: 10 if x.state == nagiosplugin.state.Ok else x.state.code,
            reverse=True,
        ):
            # We only display errors or metadata (number of ports)
            if result.state != nagiosplugin.state.Ok or result.context.name == "metadata":
                messages.append(result.hint)
        return ", ".join(messages)


class MetadataContext(nagiosplugin.Context):
    def evaluate(self, metric, resource):
        state_cls = getattr(nagiosplugin.state, metric.name)
        return self.result_cls(state=state_cls, hint=metric.value["message"], metric=metric)


class MovingCounterContext(nagiosplugin.Context):
    def evaluate(self, metric, resource):
        first_value = metric.value["values"][0]
        max_value = first_value
        for value in metric.value["values"]:
            max_value = max(max_value, value)
        if max_value > first_value:
            return self.result_cls(
                nagiosplugin.state.Warn,
                hint=f"Port {metric.value['phynum']} ({metric.value['serial']}): "
                f"{metric.name} incremented from {first_value} to {max_value}",
                metric=metric,
            )
        return self.result_cls(nagiosplugin.state.Ok, metric=metric)

    def performance(self, metric, resource):
        return nagiosplugin.performance.Performance(
            f"{metric.value['serial']}_{metric.name}", metric.value["values"][-1]
        )


# No traceback display during argument parsing
@nagiosplugin.guarded(verbose=0)
def parse_args():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter, description=__doc__
    )
    parser.add_argument(
        "--max-attempts",
        help="number of attempts required for the service to enter a hard state,"
        " this controls the number of values retained for each counter",
        type=int,
        default=4,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        help="enable more verbose output, can be specified multiple times",
        default=0,
        action="count",
    )
    return parser.parse_args()


@nagiosplugin.guarded
def main(args):
    # Unique identifier used to store check state
    relevant_args = []
    for arg, arg_val in sorted(vars(args).items()):
        if arg not in ("verbose",):
            relevant_args.append((arg, arg_val))
    args_hash = hashlib.sha1(pickle.dumps(relevant_args)).hexdigest()
    check = nagiosplugin.Check(
        LSIUtil(args, args_hash),
        nagiosplugin.ScalarContext("scalar"),
        MovingCounterContext("counter"),
        MetadataContext("metadata"),
        LSIUtilSummary(),
    )
    check.main(args.verbose)


if __name__ == "__main__":
    main(parse_args())
