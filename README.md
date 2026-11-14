# Systemd Inspector

**Expose. Explore. Explain.**

Systemd Inspector is a read-only systemd inspector for runtime units and installed unit files across the system and current-user managers, with detailed properties, relationships, provenance and selected runtime context.

Current release: **1.0.0**

Repository: <https://github.com/linspectacles/systemd-inspector>

<p align="center">
  <a href="https://github.com/brunonlinespace/brunonlinespace/blob/main/linspectacles/systemd-inspector.png">
    <img
      src="https://raw.githubusercontent.com/brunonlinespace/brunonlinespace/main/linspectacles/systemd-inspector.png"
      alt="Systemd Inspector screenshot"
      width="900"
    >
  </a>
</p>

## What Systemd Inspector is

Systemd Inspector answers a focused question: **what does systemd report about its units, unit files, manager state, dependencies and runtime resource context?**

The applet reports information available from its documented Linux sources. Data that is unavailable, restricted, or not reported by those sources remains explicitly unavailable rather than being inferred.

## Highlights

- Switchable **Runtime Units** and **Unit Files** inventories.
- System/User manager scope plus unit-type and state filtering; Runtime Units also supports a persistent failed-only filter.
- Supported unit types include service, mount, swap, socket, target, device, automount, timer, path, slice and scope.
- **Unit Details...** includes complete `systemctl show` properties, native dependency traversal, unit-file provenance and `systemctl cat` backing fragment/drop-ins.
- Focused service runtime outcome/lifecycle fields where systemd reports them.
- Native Timer, Socket and Path analysis using the corresponding systemd list commands.
- Selected unit cgroup identity and read-only runtime data from the reported cgroup path.
- Recent per-unit journal records.
- Read-only manager snapshot including manager state, default target, properties, unit paths and active jobs.
- Optional `systemd-analyze security` exposure analysis, explicitly not presented as a vulnerability or whole-system security score.

## Data sources and acquisition

- `systemctl list-units`, `list-unit-files`, `status`, `show`, `cat` and `list-dependencies`.
- `systemctl list-timers`, `list-sockets` and `list-paths` for matching unit types.
- `journalctl` for recent selected-unit journal records.
- `systemctl --version`, `is-system-running`, `get-default`, manager `show`, and `list-jobs`.
- `systemd-analyze unit-paths` and optional `systemd-analyze security`.
- `/sys/fs/cgroup/<reported-control-group>/` for selected unit cgroup runtime state.

The applet uses those sources according to the acquisition paths implemented in this release. Optional tools or privileged helpers only affect the views/actions that explicitly use them; they are not treated as silent substitutes for unrelated sources.

## Interface

Systemd Inspector follows the LinSpectacles inventory + **Metadata Details** pattern where applicable: an acquired inventory remains separate from the details for the selected record, and search/filter controls operate on the data the applet has actually collected.

The applet's **Options** surface provides the presentation/source/about controls implemented by this release, together with export controls where present in the source. Applet-specific actions remain explicit rather than being folded into background collection.

## Read-only and scope boundaries

Systemd Inspector does not start, stop, restart, enable, disable, mask or edit units and does not run daemon-reload. Ordering dependencies are not silently converted into requirement dependencies, missing properties are not invented, and systemd's security exposure analysis is not promoted into a vulnerability verdict.

## Useful keyboard shortcuts

| Command | Shortcut |
| --- | --- |
| Show / hide Metadata Details | `F3` |
| Failed units only | `Ctrl+F` |
| Toggle Runtime Units / Unit Files | `Ctrl+Shift+I` |
| Unit Details | `F4` |
| Refresh active inventory | `Shift+F5` |
| Toggle Horizontal / Vertical details | `Ctrl+L` |
| Manager view | `Ctrl+M` |
| Options | `Ctrl+/` |

## Running from source

The supplied source is directly runnable on Linux. The Python-side requirements are:

- Python 3.
- PyQt6 for the graphical interface.

Create a local virtual environment if you do not already have the required Python packages in the environment you want to use:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install PyQt6
python3 linspectacles_systemd_inspector/standalone.py
```

Linux commands, procfs/sysfs interfaces, system services, or optional helpers mentioned in **Data sources and acquisition** are applet-specific runtime inputs. Data that is unavailable, restricted, or not reported by those sources remains explicitly unavailable rather than being inferred.

No RPM installation instructions are included in this README.

## LinSpectacles Hub

This applet can run independently, but it can also be installed and used inside **[LinSpectacles Hub](https://github.com/linspectacles/linspectacles-hub)**.

LinSpectacles Hub is the optional workbench for the LinSpectacles applet family. It provides shared applet discovery, navigation and management while each inspector remains independently runnable.

To install a portable or user applet through the Hub, open **Configuration... → Applets** and add the applet ZIP. Once discovered, the applet can be enabled and opened from the Hub navigation.

System-installed applets are discovered by the Hub from its system applet store and remain managed by the system package manager.

## Source layout and LinSpectacles integration

The applet source is contained in:

```text
linspectacles_systemd_inspector/
├── __init__.py
├── applet.json
├── standalone.py
├── README.md
├── LICENSE
└── systemd_inspector/
    ├── __init__.py
    ├── applet.py
    ├── _support.py
    └── icon.png
```

`applet.json` defines the applet's LinSpectacles identity and integration metadata. `standalone.py` provides direct standalone launching, while the applet entrypoint allows the same inspector to run inside LinSpectacles Hub.

## Configuration

Presentation and inspection preferences are persisted only through the settings mechanisms already implemented by the applet. Persisted UI state does not grant the applet permission to modify the inspected Linux subsystem.

## Scope

Systemd Inspector is intentionally specialist. Related Linux information that belongs to another LinSpectacles subsystem remains outside this applet rather than being inferred or duplicated here.

## License

GNU General Public License v3.0 or later. See [`LICENSE`](LICENSE).

## Links

- LinSpectacles organisation: <https://github.com/linspectacles/>
- LinSpectacles Hub: <https://github.com/linspectacles/linspectacles-hub>
- Repository: <https://github.com/linspectacles/systemd-inspector>
- Issues: <https://github.com/linspectacles/systemd-inspector/issues>

<p align="center">
  <a href="https://github.com/linspectacles/systemd-inspector">
    <img
      src="systemd_inspector/icon.png"
      alt="Systemd Inspector"
      width="256"
    >
  </a>
</p>
