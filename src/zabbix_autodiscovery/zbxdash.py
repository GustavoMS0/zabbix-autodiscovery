"""Native Zabbix dashboards built from the data that really exists on the hosts.

Every column, graph and availability tile is chosen from the items of the hosts of the dashboard's
groups: a vendor template that names CPU "#1: CPU utilization" or temperature "Inlet Temp" is picked up,
and nothing is drawn when no host has the data. Field names follow the widget definitions of the
Zabbix frontend (ui/widgets/*/includes/WidgetForm.php).

Layout on Zabbix 7.0+ (72-column grid):
    problems by severity | host availability
    host navigator | availability honeycomb
                   | summary table (one row per host)
    graphs of the host selected in the navigator (two per row)
    problem list
Zabbix 6.x has no host navigator: the dashboard keeps the summary widgets and the problem list.
"""
import fnmatch
import random
import re
import string
from collections import defaultdict

AVAILABILITY = ["ICMP ping", "Zabbix agent ping", "SNMP agent availability", "Zabbix agent availability"]
PALETTE = ["1A7C11", "2774A4", "F63100", "A54F10", "FC6EA3", "6C59DC", "AC8C14", "611F27"]
RED, ORANGE, GREEN = "E45959", "FFA059", "59DB8F"

MIN_COVERAGE = 0.3         # a table column needs data on at least 30% of the hosts (avoids empty columns)

# Summary table columns: (label, regex on item names, display). "bar" = 0-100 % bar with thresholds.
# Regexes accept English and Portuguese names (some vendor templates are localized).
ICMP = ("Latency", r"^ICMP response time$", "value")
LOSS = ("Loss %", r"^ICMP loss$", "value")
CPU = ("CPU", r"cpu utilization|utiliza[cç][aã]o de cpu", "bar")
MEM = ("Memory", r"memory utilization|utiliza[cç][aã]o de mem[oó]ria", "bar")
UPTIME = ("Uptime", r"^(system )?uptime|uptime \((network|hardware)\)", "value")

# Graphs: (title, [(series label, [item patterns with * wildcards, any of them])])
TRAFFIC = ("Traffic", [("in", ["*Bits received*"]), ("out", ["*Bits sent*"])])
ERRORS = ("Interface errors", [("in", ["*Inbound packets with errors*"]),
                               ("out", ["*Outbound packets with errors*"])])
CPU_MEM = ("CPU and memory", [("CPU", ["*CPU utilization*"]), ("memory", ["*Memory utilization*"])])
TEMP = ("Temperature", [("temperature", ["*emperature*", "*Temp*: Value", "*emperatura*"])])
LATENCY = ("ICMP latency", [("latency", ["ICMP response time"])])

LAYOUTS = {
    "overview": {"table": [ICMP, LOSS], "graphs": [LATENCY]},
    "switches": {"table": [ICMP, ("Port usage", r"^switch: port usage$", "bar"),
                           ("Ports in use", r"^switch: ports in use$", "value"), CPU, MEM, UPTIME],
                 "graphs": [TRAFFIC, ERRORS, CPU_MEM, TEMP]},
    "routers": {"table": [ICMP, CPU, MEM, UPTIME], "graphs": [TRAFFIC, CPU_MEM, ERRORS, TEMP]},
    "firewalls": {"table": [ICMP, CPU, MEM, ("Sessions", r"session", "value"), UPTIME],
                  "graphs": [TRAFFIC, CPU_MEM, ("Sessions", [("sessions", ["*ession*"])]), ERRORS]},
    "access-points": {"table": [ICMP, ("Clients", r"client|station|associated", "value"), CPU, MEM, UPTIME],
                      "graphs": [TRAFFIC, ("Clients", [("clients", ["*lient*", "*tation*"])]), CPU_MEM]},
    "printers": {"table": [("Pages", r"^printer: total page count$", "value"),
                           ("Status", r"^printer: device status$", "value"), ICMP, UPTIME],
                 "graphs": [("Supply levels", [("level %", ["Supply *: Level %"])]),
                            ("Pages printed", [("pages", ["Printer: Total page count"])])]},
    "servers": {"table": [CPU, MEM,
                          ("Disk C: / root", r"^fs \[\(?(c:|/)\)?\]: space: used, in %$|^(c:|/): space utilization$",
                           "bar"),
                          ("Agent", r"^zabbix agent (ping|availability)$", "value"), UPTIME],
                "graphs": [CPU_MEM, ("Disk usage", [("used %", ["*Space: Used, in %*", "*Space utilization*"])]),
                           TRAFFIC]},
    "ups": {"table": [("Battery", r"(battery|bateria).*(capacity|charge|level|remaining|carga)", "bar"),
                      ("Load", r"(output|sa[ií]da).*(load|carga)|percentual de carga", "bar"),
                      ("Runtime", r"runtime|time remaining|tempo restante|autonomia", "value"),
                      ("Input voltage", r"(input|entrada).*(volt|tens)", "value"),
                      ("Battery temp.", r"(battery|bateria).*temperat", "value")],
            "graphs": [("Battery and load", [("battery", ["*attery*harge*", "*ateria*arga*"]),
                                             ("load", ["*utput*oad*", "*aida*arga*"])]),
                       ("Voltage", [("input", ["*nput*olt*", "*ntrada*ens*"]),
                                    ("output", ["*utput*olt*", "*aida*ens*"])])]},
    "storage": {"table": [ICMP, CPU, MEM, UPTIME],
                "graphs": [("Volume usage", [("used", ["*olume*used*", "*olume*sage*"])]), TEMP, TRAFFIC]},
    "server-hardware": {"table": [("Overall status", r"(overall|global|system).*(health )?status", "value"),
                                  ("CPU temp.", r"cpu\d? temp.*value|temperature", "value"), ICMP],
                        "graphs": [TEMP, ("Fans", [("fans", ["*Fan*: Speed", "*an*speed*"])])]},
    "cctv": {"table": [ICMP, LOSS, UPTIME], "graphs": [LATENCY]},
    "voip": {"table": [ICMP, LOSS, UPTIME], "graphs": [LATENCY]},
    "pdu": {"table": [("Load", r"load|current|power|carga|corrente", "value"),
                      ("Voltage", r"volt|tens", "value"), ICMP],
            "graphs": [("Load", [("load", ["*oad*", "*arga*"])]), ("Voltage", [("voltage", ["*olt*", "*ens*"])])]},
}


def _f(ftype, name, value):
    return {"type": ftype, "name": name, "value": value}


def _reference():
    return "".join(random.choice(string.ascii_uppercase) for _ in range(5))


class Catalog:
    """Items with data on the dashboard's hosts: {name: set(hostid)}."""

    def __init__(self, items, host_count=1):
        self.host_count = max(1, host_count)
        self.hosts_by_name = defaultdict(set)
        for i in items:
            if i.get("lastclock", "0") != "0" and i.get("state", "0") == "0":
                self.hosts_by_name[i["name"]].add(i["hostid"])

    def best_name(self, regex, min_coverage=MIN_COVERAGE):
        """Exact item name matching the regex that is present on the most hosts (None if too rare)."""
        rx = re.compile(regex, re.I)
        scored = [(len(h), name) for name, h in self.hosts_by_name.items() if rx.search(name)]
        if not scored:
            return None
        count, name = max(scored)
        return name if count >= max(1, round(self.host_count * min_coverage)) else None

    def has_pattern(self, pattern):
        p = pattern.lower()
        return any(fnmatch.fnmatchcase(n.lower(), p) for n in self.hosts_by_name)

    def patterns(self, candidates):
        return [p for p in candidates if self.has_pattern(p)]

    def best_availability(self):
        """First item of AVAILABILITY (ICMP preferred) covering at least 60% of the best coverage."""
        counts = {n: len(self.hosts_by_name.get(n, ())) for n in AVAILABILITY}
        top = max(counts.values())
        return next((n for n in AVAILABILITY if top and counts[n] >= 0.6 * top), None)


def _groups(groupids):
    return [_f(2, f"groupids.{i}", gid) for i, gid in enumerate(groupids)]


def _table(title, groupids, columns, version, order=("first", "top"), lines=100):
    fields = _groups(groupids) + [_f(1, "columns.0.name", "Host"), _f(0, "columns.0.data", 2)]
    for n, (label, item, display) in enumerate(columns, 1):
        fields += [_f(1, f"columns.{n}.name", label), _f(0, f"columns.{n}.data", 1),
                   _f(1, f"columns.{n}.item", item), _f(0, f"columns.{n}.decimal_places", 1 if display == "bar" else 2)]
        if display == "bar":
            fields += [_f(0, f"columns.{n}.display", 2), _f(1, f"columns.{n}.min", "0"),
                       _f(1, f"columns.{n}.max", "100"), _f(1, f"columns.{n}.base_color", GREEN),
                       _f(1, f"columnsthresholds.{n}.color.0", ORANGE),
                       _f(1, f"columnsthresholds.{n}.threshold.0", "80"),
                       _f(1, f"columnsthresholds.{n}.color.1", RED),
                       _f(1, f"columnsthresholds.{n}.threshold.1", "90")]
    column = 1 if order[0] == "first" and columns else 0
    fields += [_f(0, "column", column), _f(0, "order", 2 if order[1] == "top" else 3),
               _f(0, "show_lines" if version >= (7, 0) else "count", lines)]
    return {"type": "tophosts", "name": title, "fields": fields}


def _graph(title, datasets, default_host, reference):
    fields = []
    for n, (label, patterns) in enumerate(datasets):
        p = f"ds.{n}."
        fields += [_f(0, p + "dataset_type", 1), _f(1, p + "hosts.0", default_host)]
        fields += [_f(1, f"{p}items.{i}", pattern) for i, pattern in enumerate(patterns)]
        fields += [
                   _f(1, p + "color", PALETTE[n % len(PALETTE)]), _f(0, p + "type", 0), _f(0, p + "stacked", 0),
                   _f(0, p + "width", 2), _f(0, p + "pointsize", 3), _f(0, p + "transparency", 3),
                   _f(0, p + "fill", 1), _f(0, p + "axisy", 0), _f(1, p + "timeshift", ""),
                   _f(0, p + "missingdatafunc", 0), _f(0, p + "aggregate_function", 0),
                   _f(1, p + "aggregate_interval", "1h"), _f(0, p + "aggregate_grouping", 0),
                   _f(0, p + "approximation", 2), _f(1, p + "data_set_label", label)]
    fields.append(_f(1, "override_hostid._reference", f"{reference}._hostid"))
    return {"type": "svggraph", "name": title, "fields": fields}


def build(key, title, groupids, version, items, hostnames, agent_missing=False):
    """Widgets for dashboard.create, with x/y/width/height filled in."""
    layout = LAYOUTS.get(key, LAYOUTS["cctv"])
    cat = Catalog(items, len(hostnames) or 1)
    modern = version >= (7, 0)
    full = 72 if modern else 24
    widgets = []

    def place(widget, x, y, w, h):
        widget.update(x=x, y=y, width=w, height=h)
        widgets.append(widget)

    # row 1: counters
    place({"type": "problemsbysv", "name": f"Problems - {title}",
           "fields": _groups(groupids) + [_f(0, "show_type", 1)]}, 0, 0, full * 2 // 3, 3)
    place({"type": "hostavail", "name": "Host availability", "fields": _groups(groupids) + [_f(0, "layout", 0)]},
          full * 2 // 3, 0, full - full * 2 // 3, 3)

    columns = [(label, name, display) for label, regex, display in layout["table"]
               if (name := cat.best_name(regex))]
    availability = cat.best_availability()
    y = 3
    if modern and hostnames:
        nav_w = 16
        ref = _reference()
        place({"type": "hostnavigator", "name": "Hosts",
               "fields": _groups(groupids) + [_f(0, "show_lines", 100), _f(1, "reference", ref)]}, 0, y, nav_w, 13)
        right_x, right_w = nav_w, full - nav_w
        if availability:
            # value 0 = red, 1 = green (ICMP ping / agent ping / SNMP availability are all 0/1 items)
            thresholds = [_f(1, "thresholds.0.color", RED), _f(1, "thresholds.0.threshold", "0"),
                          _f(1, "thresholds.1.color", GREEN), _f(1, "thresholds.1.threshold", "1")]
            place({"type": "honeycomb", "name": f"Availability ({availability})",
                   "fields": _groups(groupids) + [_f(1, "items.0", availability)] + thresholds},
                  right_x, y, right_w, 4)
        if columns:
            place(_table(f"Summary - {title}", groupids, columns, version),
                  right_x, y + 4, right_w, 9)
        y += 13
        graphs = [(t, [(lbl, cat.patterns(pats)) for lbl, pats in ds if cat.patterns(pats)])
                  for t, ds in layout["graphs"]]
        graphs = [(t, ds) for t, ds in graphs if ds][:4]
        default_host = sorted(hostnames)[0]
        for n, (gtitle, datasets) in enumerate(graphs):
            place(_graph(f"{gtitle} (selected host)", datasets, default_host, ref),
                  (n % 2) * (full // 2), y + (n // 2) * 7, full // 2, 7)
        y += ((len(graphs) + 1) // 2) * 7
    elif columns:
        place(_table(f"Summary - {title}", groupids, columns, version), 0, y, full, 8)
        y += 8
    if agent_missing:
        place({"type": "problems", "name": "Servers without Zabbix agent",
               "fields": _groups(groupids) + [_f(1, "tags.0.tag", "agent"), _f(0, "tags.0.operator", 1),
                                              _f(1, "tags.0.value", "missing")]}, 0, y, full, 4)
        y += 4
    place({"type": "problems", "name": "Problems", "fields": _groups(groupids) + [_f(0, "show_lines", 25)]},
          0, y, full, 6)
    return widgets
