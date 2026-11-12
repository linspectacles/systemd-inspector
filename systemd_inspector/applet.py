#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# LinSpectacles - Linux Inspection Suite
# Copyright (C) 2026 brunonlinespace
# GPL-3.0-or-later

APPLET_ID = 'linspectacles-systemd-inspector'
APPLET_NAME = 'Systemd Inspector'
APPLET_AUTHOR = "brunonlinespace"
APPLET_EDITOR = "brunonlinespace"
APPLET_PUBLISHER = "brunonlinespace"
APPLET_ORGANIZATION_ID = "linspectacles"
APPLET_ORGANIZATION_URL = "https://github.com/linspectacles/"
APPLET_REPOSITORY = "https://github.com/linspectacles/systemd-inspector"

APPLET_VERSION = "1.0.0"

import os
import re
import subprocess
from pathlib import Path
from ._support import (
    BaseInspectorTab, ColumnVisibilityController, export_records_dialog, metadata_font_qss,
)


from PyQt6.QtCore import QSettings, QTimer, Qt, QUrl
from PyQt6.QtGui import QColor, QKeySequence, QPixmap, QShortcut, QTextCharFormat, QTextCursor
from PyQt6.QtWidgets import (
    QAbstractItemView, QButtonGroup, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QHBoxLayout, QLabel,
    QMessageBox, QPushButton, QRadioButton, QStackedWidget, QTabWidget, QTableWidget, QTableWidgetItem, QTextEdit,
    QVBoxLayout, QWidget,
)

# Properties are deliberately grouped by the interface that reports them.
# LinSpectacles displays systemd's reported values without inventing defaults for
# empty/unknown properties.
UNIT_PROPERTIES = (
    "Id", "Names", "Description", "LoadState", "ActiveState", "SubState",
    "FragmentPath", "SourcePath", "DropInPaths", "UnitFileState",
    "UnitFilePreset", "MainPID", "ControlGroup",
)

DEPENDENCY_PROPERTIES = (
    "Requires", "Wants", "Requisite", "BindsTo", "PartOf", "Upholds",
    "Conflicts", "Before", "After", "TriggeredBy", "Triggers",
)

SERVICE_PROPERTIES = (
    "Type", "User", "Group", "DynamicUser", "WorkingDirectory",
    "RootDirectory", "Restart", "RestartUSec", "TimeoutStartUSec",
    "TimeoutStopUSec", "ExecStart", "ExecReload", "ExecStop",
    "EnvironmentFiles",
)

SERVICE_RUNTIME_PROPERTIES = (
    "MainPID", "ControlPID", "Result", "ExecMainCode", "ExecMainStatus",
    "NRestarts", "InvocationID", "ExecMainStartTimestamp", "ExecMainExitTimestamp",
    "ActiveEnterTimestamp", "ActiveExitTimestamp", "InactiveEnterTimestamp",
    "StateChangeTimestamp", "ConditionResult", "AssertResult",
)

TIMER_PROPERTIES = (
    "Triggers", "TimersCalendar", "TimersMonotonic", "NextElapseUSecRealtime",
    "NextElapseUSecMonotonic", "LastTriggerUSec", "LastTriggerUSecMonotonic",
    "AccuracyUSec", "RandomizedDelayUSec", "FixedRandomDelay", "Persistent",
    "WakeSystem", "RemainAfterElapse", "OnClockChange", "OnTimezoneChange", "Result",
)

SOCKET_PROPERTIES = (
    "Triggers", "Listen", "Accept", "SocketMode", "DirectoryMode", "RemoveOnStop",
    "BindIPv6Only", "Backlog", "MaxConnections", "MaxConnectionsPerSource",
    "KeepAlive", "NoDelay", "Priority", "ReceiveBuffer", "SendBuffer",
    "PassCredentials", "PassSecurity", "ReusePort", "FreeBind", "Transparent",
    "Broadcast", "PassPacketInfo", "Timestamping", "TriggerLimitIntervalUSec",
    "TriggerLimitBurst", "Result",
)

PATH_PROPERTIES = (
    "Triggers", "Paths", "MakeDirectory", "DirectoryMode", "TriggerLimitIntervalUSec",
    "TriggerLimitBurst", "Result",
)

MANAGER_PROPERTIES = (
    "Architecture", "Tainted", "NNames", "NFailedUnits",
    "NJobs", "NInstalledJobs", "NFailedJobs", "Progress", "ControlGroup",
    "DefaultStandardOutput", "DefaultStandardError", "DefaultTimeoutStartUSec",
    "DefaultTimeoutStopUSec", "DefaultRestartUSec", "RuntimeWatchdogUSec",
    "RebootWatchdogUSec", "ServiceWatchdogs",
)

RESOURCE_PROPERTIES = (
    "CPUAccounting", "CPUWeight", "CPUQuotaPerSecUSec",
    "MemoryAccounting", "MemoryCurrent", "MemoryPeak", "MemoryHigh",
    "MemoryMax", "TasksAccounting", "TasksCurrent", "TasksMax",
    "IOAccounting", "IOWeight",
)

SANDBOX_PROPERTIES = (
    "NoNewPrivileges", "PrivateTmp", "PrivateDevices", "PrivateNetwork",
    "PrivateUsers", "ProtectSystem", "ProtectHome", "ProtectKernelTunables",
    "ProtectKernelModules", "ProtectControlGroups", "ProtectClock",
    "ProtectHostname", "RestrictSUIDSGID", "LockPersonality",
    "MemoryDenyWriteExecute", "RestrictRealtime", "SystemCallArchitectures",
    "RestrictAddressFamilies", "CapabilityBoundingSet", "AmbientCapabilities",
    "DevicePolicy", "UMask", "KeyringMode", "ProtectProc", "ProcSubset",
    "RemoveIPC",
)


ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def _manager_flag(manager_scope):
    return "--user" if str(manager_scope).lower() == "user" else "--system"


def _systemctl_command(manager_scope, *arguments):
    return ["systemctl", _manager_flag(manager_scope), *arguments]


def _systemctl_unit_command(manager_scope, command_name, unit_name, *options):
    """Build a systemctl command with a unit operand protected by `--`.

    systemd has valid unit names such as `-.mount`. Without the explicit option
    terminator, systemctl can misread those names as command-line options.
    """
    return [
        "systemctl", _manager_flag(manager_scope), command_name, *options, "--", str(unit_name)
    ]


def _journal_unit_command(manager_scope, unit_name):
    if str(manager_scope).lower() == "user":
        return [
            "journalctl", "--user", f"--user-unit={unit_name}",
            "-n", "10", "--reverse", "--no-pager",
        ]
    return [
        "journalctl", "--system", "-u", unit_name,
        "-n", "10", "--reverse", "--no-pager",
    ]


def _systemd_show_properties(unit_name, properties, timeout=8, manager_scope="system"):
    """Return exactly the requested values reported by `systemctl show`."""
    command = _systemctl_command(manager_scope, "show", "--no-pager")
    for prop in properties:
        command.extend(["--property", prop])
    command.extend(["--", str(unit_name)])
    result = subprocess.run(
        command, capture_output=True, text=True, check=False, timeout=timeout
    )
    values = {str(prop): "" for prop in properties}
    if result.stdout:
        for line in result.stdout.splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            if key in values:
                values[key] = value.strip()
    return values, result


def _systemd_show_all(unit_name, timeout=10, manager_scope="system"):
    """Return all properties exactly as reported by `systemctl show`."""
    result = subprocess.run(
        _systemctl_unit_command(manager_scope, "show", unit_name, "--no-pager"),
        capture_output=True, text=True, check=False, timeout=timeout,
    )
    values = {}
    if result.stdout:
        for line in result.stdout.splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values, result


def _visible_value(value):
    """Do not infer a missing systemd property; mark it as not reported."""
    text = str(value or "")
    return text if text else "Not reported"


def _properties_text(title, properties, values):
    lines = [title, "=" * len(title), ""]
    for prop in properties:
        lines.append(f"{prop}: {_visible_value(values.get(prop, ''))}")
    return "\n".join(lines).rstrip() + "\n"


def _apply_dialog_metadata_font(owner, text_edit):
    font = getattr(owner, "_metadata_font", None)
    if font is not None:
        text_edit.setFont(font)
        text_edit.document().setDefaultFont(font)
        text_edit.setCurrentFont(font)


def _unit_details_canvas(owner):
    """Create the Unit Details canvas using Journal Errors 0.0.1 metadata styling."""
    widget = QTextEdit()
    widget.setReadOnly(True)
    widget.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
    _apply_dialog_metadata_font(owner, widget)
    font = getattr(owner, "_metadata_font", None)
    font_rule = metadata_font_qss(font) if font is not None else ""
    widget.setStyleSheet(
        "QTextEdit { "
        f"{font_rule} "
        "background-color: #151719; color: #dcdcdc; "
        "border: 1px solid #333333; "
        "}"
    )
    return widget


def _detail_formats():
    key_format = QTextCharFormat()
    key_format.setForeground(QColor("#9cdcfe"))
    key_format.setFontWeight(600)
    value_format = QTextCharFormat()
    value_format.setForeground(QColor("#dcdcdc"))
    return key_format, value_format


def _append_section_heading(widget, heading):
    key_format, value_format = _detail_formats()
    cursor = widget.textCursor()
    cursor.movePosition(QTextCursor.MoveOperation.End)
    if cursor.position() > 0:
        cursor.insertText("\n", value_format)
    cursor.insertText(str(heading) + "\n", key_format)
    widget.setTextCursor(cursor)


def _append_property(widget, key, value):
    key_format, value_format = _detail_formats()
    cursor = widget.textCursor()
    cursor.movePosition(QTextCursor.MoveOperation.End)
    cursor.insertText(f"{key}: ", key_format)
    cursor.insertText(_visible_value(value) + "\n", value_format)
    widget.setTextCursor(cursor)


def _append_query_status(widget, error):
    if not error:
        return
    _append_section_heading(widget, "Query Status")
    _append_property(widget, "Status", error)


# `systemctl show` reports a large, unit-type-dependent property set.  Keep
# every reported property, but arrange it for human inspection rather than
# preserving the command's raw output order.
SEMANTIC_PROPERTY_GROUPS = (
    "Identity & Description",
    "Load, State & Enablement",
    "Definition, Paths & Installation",
    "Dependencies & Ordering",
    "Lifecycle, Jobs & Timing",
    "Execution, Process & Restart",
    "User, Environment & Namespace",
    "Resource Control & cgroup",
    "Security & Sandboxing",
    "Logging & Standard I/O",
    "Socket & IPC",
    "Mount, Automount & Swap",
    "Timer & Path Activation",
    "Other Reported Properties",
)


def _semantic_property_group(prop):
    p = str(prop)

    if p in {
        "Id", "Names", "Description", "Documentation", "Following",
        "InvocationID", "MachineInvocationID",
    }:
        return "Identity & Description"

    if p in {
        "LoadState", "ActiveState", "FreezerState", "SubState",
        "UnitFileState", "UnitFilePreset", "UnitFileFlags", "NeedDaemonReload",
    } or p.startswith(("ActiveState", "SubState")):
        return "Load, State & Enablement"

    if p in {
        "FragmentPath", "SourcePath", "DropInPaths", "Transient", "Perpetual",
        "Generator", "UnitFileState", "UnitFilePreset",
    } or p.startswith(("Fragment", "SourcePath", "DropIn", "UnitFile")):
        return "Definition, Paths & Installation"

    dependency_names = {
        "Requires", "Requisite", "Wants", "BindsTo", "PartOf", "Upholds",
        "Conflicts", "Before", "After", "OnFailure", "OnSuccess",
        "PropagatesReloadTo", "ReloadPropagatedFrom", "PropagatesStopTo",
        "StopPropagatedFrom", "JoinsNamespaceOf", "RequiresMountsFor",
        "WantsMountsFor", "TriggeredBy", "Triggers", "ConsistsOf", "BoundBy",
        "RequiredBy", "RequisiteOf", "WantedBy", "UpheldBy", "ConflictedBy",
    }
    if p in dependency_names or p.endswith(("By", "Of")) and p in dependency_names:
        return "Dependencies & Ordering"

    if (
        "Timestamp" in p or p.startswith(("Job", "StartLimit", "Runtime", "Timeout"))
        or p.endswith("USec")
        or p in {
            "StopWhenUnneeded", "RefuseManualStart", "RefuseManualStop",
            "AllowIsolate", "DefaultDependencies", "SurviveFinalKillSignal",
            "CollectMode", "FailureAction", "SuccessAction", "FailureActionExitStatus",
            "SuccessActionExitStatus", "JobTimeoutAction", "JobTimeoutRebootArgument",
        }
    ):
        return "Lifecycle, Jobs & Timing"

    if (
        p.startswith(("Exec", "Restart", "MainPID", "ControlPID", "Status"))
        or p in {
            "Type", "ExitType", "NotifyAccess", "PIDFile", "GuessMainPID",
            "RemainAfterExit", "BusName", "Result", "CleanResult", "OOMPolicy",
            "FileDescriptorStoreMax", "NFileDescriptorStore", "USBFunctionDescriptors",
            "USBFunctionStrings",
        }
    ):
        return "Execution, Process & Restart"

    if (
        p.startswith(("Environment", "PassEnvironment", "UnsetEnvironment"))
        or p in {
            "User", "Group", "SupplementaryGroups", "DynamicUser", "WorkingDirectory",
            "RootDirectory", "RootImage", "RootImageOptions", "RootHash", "RootHashSignature",
            "RootVerity", "PAMName", "UMask", "SetLoginEnvironment", "RuntimeDirectory",
            "RuntimeDirectoryMode", "StateDirectory", "StateDirectoryMode", "CacheDirectory",
            "CacheDirectoryMode", "LogsDirectory", "LogsDirectoryMode", "ConfigurationDirectory",
            "ConfigurationDirectoryMode",
        }
        or p.endswith("Directory") or p.endswith("DirectoryMode")
    ):
        return "User, Environment & Namespace"

    if (
        p.startswith(("CPU", "Memory", "Tasks", "IO", "IP", "ManagedOOM"))
        or p in {
            "ControlGroup", "Slice", "Delegate", "DelegateControllers", "DisableControllers",
            "CoredumpReceive", "OOMScoreAdjust", "LimitCPU", "LimitFSIZE", "LimitDATA",
            "LimitSTACK", "LimitCORE", "LimitRSS", "LimitNOFILE", "LimitAS", "LimitNPROC",
            "LimitMEMLOCK", "LimitLOCKS", "LimitSIGPENDING", "LimitMSGQUEUE", "LimitNICE",
            "LimitRTPRIO", "LimitRTTIME",
        }
        or p.startswith("Limit")
    ):
        return "Resource Control & cgroup"

    if (
        p.startswith((
            "Private", "Protect", "Restrict", "Capability", "AmbientCapabilities",
            "SystemCall", "DeviceAllow", "BindPaths", "BindReadOnlyPaths", "ReadWritePaths",
            "ReadOnlyPaths", "InaccessiblePaths", "TemporaryFileSystem", "LoadCredential",
            "ImportCredential", "SetCredential",
        ))
        or p in {
            "NoNewPrivileges", "SecureBits", "LockPersonality", "MemoryDenyWriteExecute",
            "RestrictRealtime", "RestrictSUIDSGID", "RemoveIPC", "KeyringMode", "DevicePolicy",
            "AppArmorProfile", "SELinuxContext", "SmackProcessLabel", "ProcSubset",
            "ProtectProc", "MountFlags",
        }
    ):
        return "Security & Sandboxing"

    if (
        p.startswith(("StandardInput", "StandardOutput", "StandardError", "Syslog", "Log", "TTY"))
    ):
        return "Logging & Standard I/O"

    if (
        p.startswith(("Listen", "Socket", "MaxConnections", "KeepAlive", "NoDelay", "FreeBind",
                      "BindToDevice", "PassCredentials", "PassSecurity", "ReceiveBuffer", "SendBuffer",
                      "IPTOS", "IPTTL", "Mark", "PipeSize", "MessageQueue"))
        or p in {"Accept", "RemoveOnStop", "Writable", "FlushPending"}
    ):
        return "Socket & IPC"

    if (
        p in {"What", "Where", "Options", "SloppyOptions", "LazyUnmount", "ForceUnmount",
              "DirectoryMode", "TimeoutIdleUSec", "ControlPID"}
        or p.startswith(("Mount", "Automount", "Swap"))
    ):
        return "Mount, Automount & Swap"

    if (
        p.startswith(("OnCalendar", "OnActive", "OnBoot", "OnStartup", "OnUnitActive",
                      "OnUnitInactive", "Accuracy", "RandomizedDelay", "FixedRandomDelay",
                      "PathExists", "PathChanged", "PathModified", "DirectoryNotEmpty", "MakeDirectory"))
        or p in {"Persistent", "WakeSystem", "RemainAfterElapse", "TimersCalendar", "NextElapseUSecRealtime"}
    ):
        return "Timer & Path Activation"

    return "Other Reported Properties"


def _semantic_properties_widget(owner, values, error=""):
    widget = _unit_details_canvas(owner)
    grouped = {name: [] for name in SEMANTIC_PROPERTY_GROUPS}
    for prop, value in values.items():
        grouped[_semantic_property_group(prop)].append((prop, value))

    wrote_any = False
    for group_name in SEMANTIC_PROPERTY_GROUPS:
        rows = grouped[group_name]
        if not rows:
            continue
        _append_section_heading(widget, group_name)
        for prop, value in sorted(rows, key=lambda item: item[0].casefold()):
            _append_property(widget, prop, value)
        wrote_any = True

    if not wrote_any:
        _append_property(widget, "Properties", "No properties were reported.")
    _append_query_status(widget, error)
    widget.moveCursor(QTextCursor.MoveOperation.Start)
    return widget


def _property_group_widget(owner, heading, properties, values, error=""):
    widget = _unit_details_canvas(owner)
    _append_section_heading(widget, heading)
    for prop in properties:
        _append_property(widget, prop, values.get(prop, ""))
    _append_query_status(widget, error)
    widget.moveCursor(QTextCursor.MoveOperation.Start)
    return widget


def _service_details_widget(owner, values, error=""):
    """Focused service configuration plus current/latest lifecycle outcome reported by systemd."""
    widget = _unit_details_canvas(owner)
    _append_section_heading(widget, "Service Execution / Restart")
    for prop in SERVICE_PROPERTIES:
        _append_property(widget, prop, values.get(prop, ""))

    _append_section_heading(widget, "Runtime / Outcome")
    for prop in SERVICE_RUNTIME_PROPERTIES:
        _append_property(widget, prop, values.get(prop, ""))

    _append_query_status(widget, error)
    widget.moveCursor(QTextCursor.MoveOperation.Start)
    return widget


def _native_unit_type_listing(unit_name, unit_type, manager_scope="system", timeout=10):
    """Return systemd's native specialized inventory row for timer/socket/path units."""
    commands = {
        "timer": "list-timers",
        "socket": "list-sockets",
        "path": "list-paths",
    }
    command_name = commands.get(str(unit_type or "").lower())
    if not command_name:
        return "", "Unsupported specialized unit type."
    env = os.environ.copy()
    env["SYSTEMD_COLORS"] = "0"
    env["SYSTEMD_PAGER"] = "cat"
    env["PAGER"] = "cat"
    result = subprocess.run(
        _systemctl_unit_command(
            manager_scope, command_name, unit_name, "--all", "--no-legend", "--no-pager"
        ),
        capture_output=True, text=True, check=False, timeout=timeout, env=env,
    )
    output = ANSI_RE.sub("", result.stdout or "").rstrip()
    error = ""
    if result.returncode != 0:
        error = ANSI_RE.sub(
            "", (result.stderr or f"systemctl {command_name} returned a non-zero status.").strip()
        )
    return output, error


def _unit_type_details_widget(owner, unit_name, unit_type, values, show_error="", manager_scope="system"):
    """Type-specific systemd properties plus the native specialized inventory snapshot."""
    definitions = {
        "timer": ("Timer Scheduling / Trigger", TIMER_PROPERTIES, "Timer Schedule Snapshot"),
        "socket": ("Socket Activation / Listener", SOCKET_PROPERTIES, "Socket Listener Snapshot"),
        "path": ("Path Activation / Watch", PATH_PROPERTIES, "Path Watch Snapshot"),
    }
    heading, properties, snapshot_heading = definitions[unit_type]
    widget = _unit_details_canvas(owner)
    _append_section_heading(widget, heading)
    for prop in properties:
        _append_property(widget, prop, values.get(prop, ""))
    _append_query_status(widget, show_error)

    _append_section_heading(widget, snapshot_heading)
    try:
        output, native_error = _native_unit_type_listing(
            unit_name, unit_type, manager_scope=manager_scope, timeout=10
        )
    except FileNotFoundError:
        output, native_error = "", "systemctl is not available."
    except subprocess.TimeoutExpired:
        output, native_error = "", f"systemctl list-{unit_type}s timed out."
    except Exception as exc:
        output, native_error = "", f"Specialized {unit_type} query failed: {exc}"

    if output:
        _key_format, value_format = _detail_formats()
        cursor = widget.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(output.rstrip() + "\n", value_format)
        widget.setTextCursor(cursor)
    else:
        _append_property(widget, "Snapshot", "No specialized inventory row was reported.")
    if native_error:
        _append_section_heading(widget, "Specialized Query Status")
        _append_property(widget, "Status", native_error)
    widget.moveCursor(QTextCursor.MoveOperation.Start)
    return widget


def _systemd_dependency_listing(unit_name, mode="requirements", manager_scope="system", timeout=12):
    """Return native systemctl dependency traversal for the requested relationship mode."""
    mode = str(mode or "requirements").lower()
    command = _systemctl_command(manager_scope, "list-dependencies")
    if mode == "reverse":
        command.append("--reverse")
    elif mode == "after":
        command.append("--after")
    elif mode == "before":
        command.append("--before")
    command.extend(["--all", "--plain", "--no-pager", "--", str(unit_name)])
    env = os.environ.copy()
    env["SYSTEMD_COLORS"] = "0"
    env["SYSTEMD_PAGER"] = "cat"
    env["PAGER"] = "cat"
    result = subprocess.run(
        command, capture_output=True, text=True, check=False, timeout=timeout, env=env
    )
    output = ANSI_RE.sub("", result.stdout or "").rstrip()
    error = ""
    if result.returncode != 0:
        error = ANSI_RE.sub(
            "", (result.stderr or "systemctl list-dependencies returned a non-zero status.").strip()
        )
    return output, error


class DependencyAnalysisWidget(QWidget):
    """Reported dependency properties plus native systemctl relationship traversal."""

    MODES = (
        ("Requirements", "requirements"),
        ("Reverse", "reverse"),
        ("After", "after"),
        ("Before", "before"),
    )

    def __init__(self, owner, unit_name, values, show_error="", manager_scope="system"):
        super().__init__()
        self.owner = owner
        self.unit_name = unit_name
        self.values = dict(values or {})
        self.show_error = str(show_error or "")
        self.manager_scope = "user" if str(manager_scope).lower() == "user" else "system"

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        self.view = _unit_details_canvas(owner)
        layout.addWidget(self.view, 1)

        row = QHBoxLayout()
        note = QLabel(
            "Requirements follows units required/wanted by the selected unit. Reverse shows units that "
            "require or want it. After and Before inspect systemd ordering relationships. The traversal "
            "is reported directly by systemctl list-dependencies; LinSpectacles does not convert ordering "
            "into requirement dependencies."
        )
        note.setWordWrap(True)
        row.addWidget(note, 1)
        row.addWidget(QLabel("Relationship:"))
        self.mode_combo = QComboBox()
        for label, value in self.MODES:
            self.mode_combo.addItem(label, value)
        self.mode_combo.currentIndexChanged.connect(self._refresh)
        row.addWidget(self.mode_combo)
        layout.addLayout(row)
        self._refresh()

    def _refresh(self, *_):
        mode = str(self.mode_combo.currentData() or "requirements")
        label = str(self.mode_combo.currentText() or "Requirements")
        self.view.clear()

        _append_section_heading(self.view, "Reported Dependencies / Ordering")
        for prop in DEPENDENCY_PROPERTIES:
            _append_property(self.view, prop, self.values.get(prop, ""))
        _append_query_status(self.view, self.show_error)

        _append_section_heading(self.view, f"Native Dependency Traversal — {label}")
        try:
            output, error = _systemd_dependency_listing(
                self.unit_name, mode, self.manager_scope, timeout=12
            )
        except FileNotFoundError:
            output, error = "", "systemctl is not available."
        except subprocess.TimeoutExpired:
            output, error = "", "systemctl list-dependencies timed out."
        except Exception as exc:
            output, error = "", f"systemctl list-dependencies failed: {exc}"

        if output:
            _key_format, value_format = _detail_formats()
            cursor = self.view.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            cursor.insertText(output.rstrip() + "\n", value_format)
            self.view.setTextCursor(cursor)
        else:
            _append_property(self.view, "Traversal", "No dependency traversal was reported.")
        if error:
            _append_section_heading(self.view, "Dependency Query Status")
            _append_property(self.view, "Status", error)
        self.view.moveCursor(QTextCursor.MoveOperation.Start)


def _systemd_cat_unit(unit_name, manager_scope="system", timeout=10):
    """Return systemd's reported backing unit/drop-in files through systemctl cat."""
    env = os.environ.copy()
    env["SYSTEMD_COLORS"] = "0"
    env["SYSTEMD_PAGER"] = "cat"
    env["PAGER"] = "cat"
    result = subprocess.run(
        _systemctl_unit_command(manager_scope, "cat", unit_name, "--no-pager"),
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
        env=env,
    )
    output = ANSI_RE.sub("", result.stdout or "")
    error = ""
    if result.returncode != 0:
        error = ANSI_RE.sub(
            "", (result.stderr or "systemctl cat returned a non-zero status.").strip()
        )
    return output.rstrip(), error


def _unit_file_provenance_widget(owner, unit_name, values, show_error="", manager_scope="system"):
    """Structured unit-file provenance plus systemd's effective fragment/drop-ins."""
    widget = _unit_details_canvas(owner)
    _append_section_heading(widget, "Unit File Provenance")
    labels = (
        ("FragmentPath", "Fragment Path"),
        ("SourcePath", "Source Path"),
        ("DropInPaths", "Drop-In Paths"),
        ("UnitFileState", "Unit File State"),
        ("UnitFilePreset", "Unit File Preset"),
        ("NeedDaemonReload", "Need Daemon Reload"),
    )
    for prop, label in labels:
        _append_property(widget, label, values.get(prop, ""))

    if show_error:
        _append_section_heading(widget, "Property Query Status")
        _append_property(widget, "Status", show_error)

    _append_section_heading(widget, "Effective Unit File / Drop-ins")
    try:
        content, cat_error = _systemd_cat_unit(
            unit_name, manager_scope=manager_scope, timeout=10
        )
    except FileNotFoundError:
        content = ""
        cat_error = "systemctl is not available."
    except subprocess.TimeoutExpired:
        content = ""
        cat_error = "systemctl cat timed out."
    except Exception as exc:
        content = ""
        cat_error = f"systemctl cat failed: {exc}"

    if content:
        _key_format, value_format = _detail_formats()
        cursor = widget.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(content.rstrip() + "\n", value_format)
        widget.setTextCursor(cursor)
    else:
        _append_property(widget, "Content", "No unit-file content was reported.")

    if cat_error:
        _append_section_heading(widget, "Unit File Content Query Status")
        _append_property(widget, "Status", cat_error)

    widget.moveCursor(QTextCursor.MoveOperation.Start)
    return widget


def _readonly_text(owner, text=""):
    widget = QTextEdit()
    widget.setReadOnly(True)
    widget.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
    _apply_dialog_metadata_font(owner, widget)
    widget.setPlainText(text)
    return widget


class TextInspectionDialog(QDialog):
    def __init__(self, owner, title, text):
        super().__init__(owner)
        self.setWindowTitle(title)
        self.resize(900, 650)
        layout = QVBoxLayout(self)
        view = _readonly_text(owner, text)
        layout.addWidget(view, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


class UnitDetailsDialog(QDialog):
    """Structured, read-only view of systemd-reported properties."""

    def __init__(self, owner, service_name, manager_scope="system"):
        super().__init__(owner)
        self.owner = owner
        self.service_name = service_name
        self.manager_scope = "user" if str(manager_scope).lower() == "user" else "system"
        self.setWindowTitle(f"Unit Details — {service_name}")
        self.resize(980, 720)

        root = QVBoxLayout(self)
        manager_label = "User" if self.manager_scope == "user" else "System"
        note = QLabel(
            "Properties below are reported by systemd through systemctl show; the Service tab includes "
            "current/latest runtime outcome and lifecycle fields, while Timer/Socket/Path units gain native "
            "type-specific analysis tabs and the Unit File tab also shows systemd's own systemctl cat "
            "view of the backing fragment and drop-ins. "
            "LinSpectacles does not infer values that systemd does not report. "
            f"Manager scope: {manager_label}."
        )
        note.setWordWrap(True)
        root.addWidget(note)

        tabs = QTabWidget()
        root.addWidget(tabs, 1)

        groups = (
            ("Service", SERVICE_PROPERTIES, "Service Execution / Restart"),
            ("Resources", RESOURCE_PROPERTIES, "Resource Control"),
            ("Sandbox", SANDBOX_PROPERTIES, "Security / Sandbox Settings"),
        )

        try:
            values, result = _systemd_show_all(service_name, timeout=10, manager_scope=self.manager_scope)
            error = ""
            if result.returncode != 0:
                error = (result.stderr or "systemctl show returned a non-zero status.").strip()
        except FileNotFoundError:
            values = {}
            error = "systemctl is not available."
        except subprocess.TimeoutExpired:
            values = {}
            error = "systemctl show timed out."
        except Exception as exc:
            values = {}
            error = f"systemctl show failed: {exc}"

        all_page = QWidget()
        all_layout = QVBoxLayout(all_page)
        all_layout.addWidget(_semantic_properties_widget(owner, values, error), 1)
        tabs.addTab(all_page, "All Properties")

        dependency_page = DependencyAnalysisWidget(
            owner,
            service_name,
            values,
            error,
            manager_scope=self.manager_scope,
        )
        tabs.addTab(dependency_page, "Dependencies")

        unit_file_page = QWidget()
        unit_file_layout = QVBoxLayout(unit_file_page)
        unit_file_layout.addWidget(
            _unit_file_provenance_widget(
                owner,
                service_name,
                values,
                error,
                manager_scope=self.manager_scope,
            ),
            1,
        )
        unit_file_note = QLabel(
            "Structured provenance is reported by systemctl show. The canvas above is systemd's own "
            "systemctl cat view of the backing unit fragment and any drop-ins; LinSpectacles does not "
            "merge or reinterpret these files."
        )
        unit_file_note.setWordWrap(True)
        unit_file_layout.addWidget(unit_file_note)
        tabs.addTab(unit_file_page, "Unit File")

        unit_type = service_name.rsplit(".", 1)[-1].lower() if "." in service_name else ""
        if unit_type in {"timer", "socket", "path"}:
            type_page = QWidget()
            type_layout = QVBoxLayout(type_page)
            type_layout.addWidget(
                _unit_type_details_widget(
                    owner, service_name, unit_type, values, error, manager_scope=self.manager_scope
                ),
                1,
            )
            native_name = {
                "timer": "list-timers",
                "socket": "list-sockets",
                "path": "list-paths",
            }[unit_type]
            type_note = QLabel(
                f"The canvas combines unit-type properties reported by systemctl show with systemd's "
                f"native {native_name} snapshot for this unit. LinSpectacles does not synthesize schedule, "
                "listener, or path-watch state that systemd does not report."
            )
            type_note.setWordWrap(True)
            type_layout.addWidget(type_note)
            tabs.addTab(type_page, unit_type.title())

        for tab_name, props, heading in groups:
            page = QWidget()
            page_layout = QVBoxLayout(page)
            if tab_name == "Service":
                page_layout.addWidget(_service_details_widget(owner, values, error), 1)
            else:
                page_layout.addWidget(
                    _property_group_widget(owner, heading, props, values, error), 1
                )

            if tab_name == "Sandbox":
                row = QHBoxLayout()
                hint = QLabel(
                    "Optional: ask systemd to analyze its own per-service sandboxing settings."
                )
                hint.setWordWrap(True)
                row.addWidget(hint, 1)
                security_btn = QPushButton("Security Analysis...")
                security_btn.clicked.connect(self._show_security_analysis)
                row.addWidget(security_btn)
                page_layout.addLayout(row)

            tabs.addTab(page, tab_name)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

    def _show_security_analysis(self):
        try:
            text = _systemd_security_analysis(self.service_name, self.manager_scope)
            dialog = TextInspectionDialog(
                self,
                f"systemd Security Analysis — {self.service_name}",
                text,
            )
            dialog.exec()
        except Exception as exc:
            QMessageBox.critical(
                self,
                "Systemd Security Analysis",
                f"Could not open the security analysis:\n{exc}",
            )


def _manager_command(command, timeout=6):
    """Run one read-only manager query and return cleaned output, stderr, and status."""
    env = os.environ.copy()
    env["SYSTEMD_COLORS"] = "0"
    env["SYSTEMD_PAGER"] = "cat"
    env["PAGER"] = "cat"
    result = subprocess.run(
        command, capture_output=True, text=True, check=False, timeout=timeout, env=env
    )
    stdout = ANSI_RE.sub("", result.stdout or "").strip()
    stderr = ANSI_RE.sub("", result.stderr or "").strip()
    return stdout, stderr, result.returncode


def _manager_show_values(manager_scope="system", timeout=6):
    """Return manager properties exactly as reported by `systemctl show` with no unit operand."""
    stdout, stderr, returncode = _manager_command(
        _systemctl_command(manager_scope, "show", "--no-pager"), timeout=timeout
    )
    values = {}
    for line in stdout.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    error = ""
    if returncode != 0:
        error = stderr or "systemctl show returned a non-zero status."
    return values, error


class ManagerAnalysisWidget(QWidget):
    """Read-only snapshot of the currently selected systemd manager."""

    def __init__(self, owner):
        super().__init__()
        self.owner = owner

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        self.view = _unit_details_canvas(owner)
        layout.addWidget(self.view, 1)

        row = QHBoxLayout()
        note = QLabel(
            "Read-only snapshot of the currently selected System/User systemd manager. "
            "Refresh Manager reruns the native manager-state, default-target, property, unit-path, "
            "and job queries; no daemon reload or other state-changing operation is performed."
        )
        note.setWordWrap(True)
        row.addWidget(note, 1)
        self.refresh_button = QPushButton("Refresh Manager")
        self.refresh_button.clicked.connect(self._refresh)
        row.addWidget(self.refresh_button)
        layout.addLayout(row)

        self._loaded = False
        _append_section_heading(self.view, "Manager Snapshot")
        _append_property(self.view, "Status", "Open this tab to query the selected systemd manager.")
        self.view.moveCursor(QTextCursor.MoveOperation.Start)

    def ensure_loaded(self):
        if not self._loaded:
            self._refresh()

    def _refresh(self):
        self._loaded = True
        manager_scope = "user" if str(self.owner.manager_scope).lower() == "user" else "system"
        manager_label = "User" if manager_scope == "user" else "System"
        self.view.clear()

        errors = []

        # systemd build/version is global to the installed userspace, while the remaining
        # queries are scoped to the selected system or user manager.
        try:
            version_out, version_err, version_rc = _manager_command(["systemctl", "--version"], timeout=4)
        except FileNotFoundError:
            version_out, version_err, version_rc = "", "systemctl is not available.", 127
        except subprocess.TimeoutExpired:
            version_out, version_err, version_rc = "", "systemctl --version timed out.", 124
        except Exception as exc:
            version_out, version_err, version_rc = "", f"systemctl --version failed: {exc}", 1

        version_lines = [line.strip() for line in version_out.splitlines() if line.strip()]
        version_line = version_lines[0] if version_lines else ""
        features_line = version_lines[1] if len(version_lines) > 1 else ""
        if version_rc != 0 and not version_out:
            errors.append(f"Version: {version_err or 'query failed.'}")

        try:
            state_out, state_err, state_rc = _manager_command(
                _systemctl_command(manager_scope, "is-system-running"), timeout=6
            )
        except FileNotFoundError:
            state_out, state_err, state_rc = "", "systemctl is not available.", 127
        except subprocess.TimeoutExpired:
            state_out, state_err, state_rc = "", "is-system-running timed out.", 124
        except Exception as exc:
            state_out, state_err, state_rc = "", f"is-system-running failed: {exc}", 1
        # is-system-running deliberately uses non-zero exit codes for valid states such as
        # degraded/offline; a reported stdout state therefore remains valid information.
        if not state_out and (state_rc != 0 or state_err):
            errors.append(f"System State: {state_err or f'exit status {state_rc}'}")

        try:
            default_out, default_err, default_rc = _manager_command(
                _systemctl_command(manager_scope, "get-default"), timeout=6
            )
        except FileNotFoundError:
            default_out, default_err, default_rc = "", "systemctl is not available.", 127
        except subprocess.TimeoutExpired:
            default_out, default_err, default_rc = "", "get-default timed out.", 124
        except Exception as exc:
            default_out, default_err, default_rc = "", f"get-default failed: {exc}", 1
        if default_rc != 0:
            errors.append(f"Default Target: {default_err or f'exit status {default_rc}'}")

        try:
            manager_values, manager_error = _manager_show_values(manager_scope, timeout=6)
        except FileNotFoundError:
            manager_values, manager_error = {}, "systemctl is not available."
        except subprocess.TimeoutExpired:
            manager_values, manager_error = {}, "systemctl show timed out."
        except Exception as exc:
            manager_values, manager_error = {}, f"systemctl show failed: {exc}"
        if manager_error:
            errors.append(f"Manager Properties: {manager_error}")

        try:
            paths_out, paths_err, paths_rc = _manager_command(
                ["systemd-analyze", _manager_flag(manager_scope), "unit-paths"], timeout=6
            )
        except FileNotFoundError:
            paths_out, paths_err, paths_rc = "", "systemd-analyze is not available.", 127
        except subprocess.TimeoutExpired:
            paths_out, paths_err, paths_rc = "", "systemd-analyze unit-paths timed out.", 124
        except Exception as exc:
            paths_out, paths_err, paths_rc = "", f"systemd-analyze unit-paths failed: {exc}", 1
        if paths_rc != 0:
            errors.append(f"Unit Search Paths: {paths_err or f'exit status {paths_rc}'}")

        try:
            jobs_out, jobs_err, jobs_rc = _manager_command(
                _systemctl_command(manager_scope, "list-jobs", "--no-pager"),
                timeout=6,
            )
        except FileNotFoundError:
            jobs_out, jobs_err, jobs_rc = "", "systemctl is not available.", 127
        except subprocess.TimeoutExpired:
            jobs_out, jobs_err, jobs_rc = "", "systemctl list-jobs timed out.", 124
        except Exception as exc:
            jobs_out, jobs_err, jobs_rc = "", f"systemctl list-jobs failed: {exc}", 1
        if jobs_rc != 0:
            errors.append(f"Current Jobs: {jobs_err or f'exit status {jobs_rc}'}")

        _append_section_heading(self.view, "Manager Overview")
        _append_property(self.view, "Manager", manager_label)
        _append_property(self.view, "System State", state_out.splitlines()[0] if state_out else "")
        _append_property(self.view, "Default Target", default_out.splitlines()[0] if default_out else "")
        _append_property(self.view, "systemd Version", version_line)
        _append_property(self.view, "Features", features_line)

        _append_section_heading(self.view, "Manager Properties")
        for prop in MANAGER_PROPERTIES:
            _append_property(self.view, prop, manager_values.get(prop, ""))

        _append_section_heading(self.view, "Unit Search Paths")
        if paths_out:
            _key_format, value_format = _detail_formats()
            cursor = self.view.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            cursor.insertText(paths_out.rstrip() + "\n", value_format)
            self.view.setTextCursor(cursor)
        else:
            _append_property(self.view, "Paths", "")

        _append_section_heading(self.view, "Current Jobs")
        if jobs_out:
            _key_format, value_format = _detail_formats()
            cursor = self.view.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            cursor.insertText(jobs_out.rstrip() + "\n", value_format)
            self.view.setTextCursor(cursor)
        elif jobs_rc == 0:
            _append_property(self.view, "Jobs", "No jobs reported.")
        else:
            _append_property(self.view, "Jobs", "")

        if errors:
            _append_section_heading(self.view, "Query Status")
            for message in errors:
                _append_property(self.view, "Status", message)

        self.view.moveCursor(QTextCursor.MoveOperation.Start)


def _systemd_security_analysis(service_name, manager_scope="system"):
    """Return systemd's own analysis verbatim (apart from ANSI colour escapes)."""
    preface = (
        "systemd Security / Sandboxing Analysis\n"
        "========================================\n\n"
        "This is systemd-analyze security's assessment of systemd-provided "
        "per-service sandboxing settings. It is not a vulnerability scan, "
        "not a measure of application-internal security, and not a statement "
        "that a service is safe or unsafe.\n\n"
        f"Manager: {'User' if str(manager_scope).lower() == 'user' else 'System'}\n"
        f"Unit: {service_name}\n\n"
    )
    env = os.environ.copy()
    env["SYSTEMD_COLORS"] = "0"
    env["SYSTEMD_PAGER"] = "cat"
    env["PAGER"] = "cat"
    try:
        result = subprocess.run(
            ["systemd-analyze", _manager_flag(manager_scope), "security", "--no-pager", "--", service_name],
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
            env=env,
        )
    except FileNotFoundError:
        return preface + "systemd-analyze is not available on this system.\n"
    except subprocess.TimeoutExpired:
        return preface + "systemd-analyze security timed out.\n"
    except Exception as exc:
        return preface + f"Could not run systemd-analyze security: {exc}\n"

    output = result.stdout or result.stderr or "No output was returned."
    output = ANSI_RE.sub("", output)
    if result.returncode != 0:
        return preface + f"Command exit status: {result.returncode}\n\n{output.rstrip()}\n"
    return preface + output.rstrip() + "\n"


def _sources_text():
    return """Systemd Inspector is read-only. Its displayed facts come from systemd commands and explicitly listed system interfaces.

Unit inventory — all unit types
  systemctl [--system|--user] list-units --all --no-legend --no-pager

Unit inventory — selected unit type
  systemctl [--system|--user] list-units --type=<unit-type> --all --no-legend --no-pager

Unit-file inventory — all unit types
  systemctl [--system|--user] list-unit-files --all --no-legend --no-pager

Unit-file inventory — selected unit type
  systemctl [--system|--user] list-unit-files --type=<unit-type> --all --no-legend --no-pager

Supported unit types
  service, mount, swap, socket, target, device, automount, timer, path, slice, scope

Selected unit status
  systemctl [--system|--user] status <unit> --no-pager --lines=0

Complete unit properties / service runtime outcome
  systemctl [--system|--user] show <unit> --no-pager
  Service tab reads MainPID, ControlPID, Result, ExecMainCode, ExecMainStatus, NRestarts,
  InvocationID, execution/state timestamps, ConditionResult, and AssertResult when reported.

Unit-file provenance / effective fragment and drop-ins
  systemctl [--system|--user] show <unit> --no-pager
  systemctl [--system|--user] cat <unit> --no-pager

Dependency analysis
  Requirements: systemctl [--system|--user] list-dependencies --all --plain --no-pager <unit>
  Reverse:      systemctl [--system|--user] list-dependencies --reverse --all --plain --no-pager <unit>
  After:        systemctl [--system|--user] list-dependencies --after --all --plain --no-pager <unit>
  Before:       systemctl [--system|--user] list-dependencies --before --all --plain --no-pager <unit>

Type-specific unit analysis
  Timer:  systemctl [--system|--user] show <timer> --no-pager
          systemctl [--system|--user] list-timers --all --no-legend --no-pager <timer>
  Socket: systemctl [--system|--user] show <socket> --no-pager
          systemctl [--system|--user] list-sockets --all --no-legend --no-pager <socket>
  Path:   systemctl [--system|--user] show <path> --no-pager
          systemctl [--system|--user] list-paths --all --no-legend --no-pager <path>

Systemd manager snapshot
  systemctl --version
  systemctl [--system|--user] is-system-running
  systemctl [--system|--user] get-default
  systemctl [--system|--user] show --no-pager
  systemd-analyze [--system|--user] unit-paths
  systemctl [--system|--user] list-jobs --no-pager

Recent journal
  system: journalctl --system -u <unit> -n 10 --reverse --no-pager
  user:   journalctl --user --user-unit=<unit> -n 10 --reverse --no-pager

Control group identity
  systemctl [--system|--user] show <unit> --property=ControlGroup --property=MainPID

Control group runtime data
  /sys/fs/cgroup/<reported-control-group>/
  cgroup.controllers
  cgroup.subtree_control
  memory.current / memory.max
  pids.current / pids.max
  cpu.weight / cpu.stat
  io.weight
  cgroup.procs

Optional security/sandbox analysis
  systemd-analyze [--system|--user] security --no-pager <unit>

  LinSpectacles reports these interfaces separately. It does not infer missing
  systemd properties, convert ordering dependencies into requirement
  dependencies, or treat systemd's security exposure analysis as a vulnerability
  or overall system-security score.
"""


def _configured_inventory_command(owner):
    """Return the exact native command for the currently selected main inventory."""
    command_name = "list-unit-files" if bool(getattr(owner, "unit_files_enabled", False)) else "list-units"
    command = _systemctl_command(getattr(owner, "manager_scope", "system"), command_name)
    unit_type_combo = getattr(owner, "unit_type_combo", None)
    unit_type = str(unit_type_combo.currentData() or "") if unit_type_combo is not None else ""
    if unit_type:
        command.append(f"--type={unit_type}")
    command.extend(["--all", "--no-legend", "--no-pager"])
    return command


def _populate_sources_canvas(canvas, owner):
    """Render static provenance plus the exact currently configured inventory query."""
    source_key_format, source_value_format = _detail_formats()
    canvas.clear()
    cursor = canvas.textCursor()
    cursor.movePosition(QTextCursor.MoveOperation.End)
    for line in _sources_text().splitlines():
        if line and not line[:1].isspace() and not set(line) <= {"="}:
            cursor.insertText(line + "\n", source_key_format)
        else:
            cursor.insertText(line + "\n", source_value_format)
    cursor.insertText("\nCurrent configured inventory query\n", source_key_format)
    cursor.insertText("  " + " ".join(_configured_inventory_command(owner)) + "\n", source_value_format)
    canvas.setTextCursor(cursor)
    canvas.moveCursor(QTextCursor.MoveOperation.Start)


def _show_sources_dialog(owner):
    dialog = QDialog(owner)
    dialog.setWindowTitle("Systemd Inspector - Data Sources")
    dialog.resize(720, 560)
    layout = QVBoxLayout(dialog)
    layout.setContentsMargins(12, 12, 12, 12)
    layout.setSpacing(10)

    heading = QLabel("Data Sources")
    font = heading.font()
    font.setBold(True)
    font.setPointSize(max(font.pointSize(), 11))
    heading.setFont(font)
    layout.addWidget(heading)

    note = QLabel("Commands and system interfaces used by each read-only Systemd Inspector view.")
    note.setWordWrap(True)
    layout.addWidget(note)

    text = _unit_details_canvas(owner)
    _populate_sources_canvas(text, owner)
    layout.addWidget(text, 1)

    buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
    buttons.rejected.connect(dialog.reject)
    buttons.accepted.connect(dialog.accept)
    layout.addWidget(buttons)
    dialog.exec()



class SystemdOptionsDialog(QDialog):
    """Tabbed Systemd Inspector options using established LinSpectacles dialog patterns."""

    def __init__(self, owner):
        super().__init__(owner)
        self.owner = owner
        self.setWindowTitle("Options — Systemd Inspector")
        self.resize(980, 720)

        root = QVBoxLayout(self)
        tabs = QTabWidget()
        root.addWidget(tabs, 1)

        # Configuration — Journal Inspector-style unified behavior and appearance controls.
        configuration_page = QWidget()
        configuration_layout = QVBoxLayout(configuration_page)
        configuration_layout.setContentsMargins(12, 12, 12, 12)
        configuration_layout.setSpacing(10)

        configuration_heading = QLabel("Systemd configuration")
        configuration_heading_font = configuration_heading.font()
        configuration_heading_font.setBold(True)
        configuration_heading.setFont(configuration_heading_font)
        configuration_layout.addWidget(configuration_heading)

        configuration_note = QLabel(
            "Inventory and Metadata Details settings are remembered. Runtime Units and Unit Files "
            "remain separate native systemd inventories; Search, State, and Failed units only are local filters."
        )
        configuration_note.setWordWrap(True)
        configuration_layout.addWidget(configuration_note)

        layout_row = QHBoxLayout()
        layout_row.addWidget(QLabel("Record details layout:"))
        self.layout_combo = QComboBox()
        self.layout_combo.addItems(["Horizontal", "Vertical"])
        self.layout_combo.setCurrentIndex(
            1 if owner.details_orientation == "vertical" else 0
        )
        self.layout_combo.currentTextChanged.connect(self._layout_changed)
        layout_row.addWidget(self.layout_combo)
        layout_row.addStretch(1)
        configuration_layout.addLayout(layout_row)

        self.show_metadata_panel = QCheckBox("Show Metadata Details panel (F3)")
        self.show_metadata_panel.setChecked(owner.metadata_panel_visible)
        self.show_metadata_panel.toggled.connect(self._metadata_panel_changed)
        configuration_layout.addWidget(self.show_metadata_panel)

        inventory_row = QHBoxLayout()
        inventory_row.addWidget(QLabel("Inventory:"))
        self.runtime_units = QRadioButton("Runtime Units")
        self.unit_files = QRadioButton("Unit Files")
        self.inventory_group = QButtonGroup(self)
        self.inventory_group.setExclusive(True)
        self.inventory_group.addButton(self.runtime_units)
        self.inventory_group.addButton(self.unit_files)
        self.runtime_units.setChecked(not owner.unit_files_enabled)
        self.unit_files.setChecked(owner.unit_files_enabled)
        self.runtime_units.toggled.connect(self._runtime_units_selected)
        self.unit_files.toggled.connect(self._unit_files_selected)
        inventory_row.addWidget(self.runtime_units)
        inventory_row.addWidget(self.unit_files)
        inventory_row.addStretch(1)
        configuration_layout.addLayout(inventory_row)

        self.failed_units_only = QCheckBox("Failed units only (Ctrl+F)")
        self.failed_units_only.setChecked(owner.failed_units_only)
        self.failed_units_only.toggled.connect(self._failed_units_only_changed)
        configuration_layout.addWidget(self.failed_units_only)

        unit_files_note = QLabel(
            "Runtime Units inspects units currently known to the selected systemd manager using list-units. "
            "Unit Files inspects installed/configured unit files using list-unit-files. Manager and Unit Type "
            "continue to scope either inventory. Search and the State selector remain local filters. "
            "Failed units only applies to Runtime Units; its preference is retained while Unit Files is selected. "
            "Ctrl+Shift+I toggles between the two inventories."
        )
        unit_files_note.setWordWrap(True)
        configuration_layout.addWidget(unit_files_note)

        shortcut_note = QLabel(
            "Shortcuts: F3 hides/restores Metadata Details; F4 opens Unit Details for the selected unit; "
            "Shift+F5 refreshes the active inventory; Ctrl+L toggles Horizontal/Vertical; "
            "Ctrl+Shift+I toggles Runtime Units/Unit Files; Ctrl+M toggles System/User Manager; "
            "Ctrl+F toggles Failed units only while Runtime Units is active; Ctrl+/ opens Options."
        )
        shortcut_note.setWordWrap(True)
        configuration_layout.addWidget(shortcut_note)
        configuration_layout.addStretch(1)
        tabs.addTab(configuration_page, "Configuration")

        # Manager — systemd-wide read-only state for the currently selected manager.
        manager_page = QWidget()
        manager_layout = QVBoxLayout(manager_page)
        manager_layout.setContentsMargins(12, 12, 12, 12)
        manager_layout.setSpacing(10)

        manager_heading = QLabel("Systemd Manager")
        manager_heading_font = manager_heading.font()
        manager_heading_font.setBold(True)
        manager_heading.setFont(manager_heading_font)
        manager_layout.addWidget(manager_heading)

        manager_note = QLabel(
            "Whole-manager state for the currently selected System/User scope: overall running state, "
            "default target, reported manager properties, unit search paths, and current jobs."
        )
        manager_note.setWordWrap(True)
        manager_layout.addWidget(manager_note)
        self.manager_analysis = ManagerAnalysisWidget(owner)
        manager_layout.addWidget(self.manager_analysis, 1)
        manager_tab_index = tabs.addTab(manager_page, "Manager")
        tabs.currentChanged.connect(
            lambda index: self.manager_analysis.ensure_loaded() if index == manager_tab_index else None
        )

        # Sources — embeds the former Systemd Inspector Data Sources dialog.
        sources_page = QWidget()
        sources_layout = QVBoxLayout(sources_page)
        sources_layout.setContentsMargins(12, 12, 12, 12)
        sources_layout.setSpacing(10)

        sources_heading = QLabel("Data Sources")
        sources_heading_font = sources_heading.font()
        sources_heading_font.setBold(True)
        sources_heading_font.setPointSize(max(sources_heading_font.pointSize(), 11))
        sources_heading.setFont(sources_heading_font)
        sources_layout.addWidget(sources_heading)

        sources_note = QLabel(
            "Commands and system interfaces used by each read-only Systemd Inspector view."
        )
        sources_note.setWordWrap(True)
        sources_layout.addWidget(sources_note)

        self.sources_text = _unit_details_canvas(owner)
        _populate_sources_canvas(self.sources_text, owner)
        sources_layout.addWidget(self.sources_text, 1)
        sources_tab_index = tabs.addTab(sources_page, "Sources")
        tabs.currentChanged.connect(
            lambda index: _populate_sources_canvas(self.sources_text, self.owner)
            if index == sources_tab_index else None
        )

        # Export — preserve the existing Systemd Inspector export fields, now selectable.
        export_page = QWidget()
        export_layout = QVBoxLayout(export_page)
        export_layout.setContentsMargins(12, 12, 12, 12)
        export_layout.setSpacing(10)

        export_heading = QLabel("Export details")
        export_heading_font = export_heading.font()
        export_heading_font.setBold(True)
        export_heading.setFont(export_heading_font)
        export_layout.addWidget(export_heading)

        export_note = QLabel(
            "Select the Systemd Inspector details to include in the export."
        )
        export_note.setWordWrap(True)
        export_layout.addWidget(export_note)

        self.export_manager = QCheckBox("Manager")
        self.export_unit = QCheckBox("Unit")
        self.export_description = QCheckBox("Description")
        self.export_load = QCheckBox("Load")
        self.export_status = QCheckBox("State")
        self.export_sub = QCheckBox("Sub State")
        self.export_unit_file = QCheckBox("Unit File")
        self.export_state = QCheckBox("State")
        self.export_preset = QCheckBox("Preset")
        self.export_metadata = QCheckBox("Metadata Details")
        for checkbox in (
            self.export_manager,
            self.export_unit,
            self.export_description,
            self.export_load,
            self.export_status,
            self.export_sub,
            self.export_unit_file,
            self.export_state,
            self.export_preset,
        ):
            checkbox.setChecked(True)
            export_layout.addWidget(checkbox)
        self.export_metadata.setChecked(False)
        export_layout.addWidget(self.export_metadata)
        self._sync_export_mode()

        export_layout.addStretch(1)
        export_row = QHBoxLayout()
        export_row.addStretch(1)
        export_button = QPushButton("Export...")
        export_button.clicked.connect(self._export_selected)
        export_row.addWidget(export_button)
        export_layout.addLayout(export_row)
        tabs.addTab(export_page, "Export")

        # About — adapted from the Suite/Boot Inspector About composition.
        about_page = QWidget()
        about_layout = QVBoxLayout(about_page)
        about_layout.setContentsMargins(24, 20, 24, 18)
        about_layout.setSpacing(8)

        icon_label = QLabel()
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_label.setFixedSize(112, 112)
        icon_path = Path(__file__).resolve().parent / "icon.png"
        if icon_path.is_file():
            pixmap = QPixmap(str(icon_path))
            if not pixmap.isNull():
                icon_label.setPixmap(
                    pixmap.scaled(
                        112,
                        112,
                        Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation,
                    )
                )
        about_layout.addWidget(icon_label, alignment=Qt.AlignmentFlag.AlignHCenter)

        name = QLabel("<h2 style='margin:0'>Systemd Inspector</h2>")
        name.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(name)

        version = QLabel(f"Version {APPLET_VERSION}")
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(version)

        slogan = QLabel("<b>Expose. Explore. Explain.</b>")
        slogan.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(slogan)

        description = QLabel(
            "A read-only LinSpectacles applet for system and current-user systemd managers, runtime units and installed unit files, "
            "with whole-manager state/jobs, live unit status, cgroup/runtime state, recent journal records, reported unit properties, "
            "native dependency traversal and unit-file provenance."
        )
        description.setWordWrap(True)
        description.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(description)

        details = QLabel(
            "<b>Build:</b> Standalone LinSpectacles applet<br>"
            "<b>Organisation ID:</b> "
            f"<a href='{APPLET_ORGANIZATION_URL}'>{APPLET_ORGANIZATION_ID}</a><br>"
            f"<b>Applet ID:</b> {APPLET_ID}"
        )
        details.setWordWrap(True)
        details.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextBrowserInteraction
            | Qt.TextInteractionFlag.TextSelectableByMouse
        )
        details.setOpenExternalLinks(True)
        details.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(details)

        copyright_label = QLabel(
            "Copyright © 2026 "
            "<a href='https://github.com/brunonlinespace'>brunonlinespace</a>"
        )
        copyright_label.setOpenExternalLinks(True)
        copyright_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(copyright_label)

        license_label = QLabel("Licensed under GNU GPLv3 or later.")
        license_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(license_label)

        readme_url = QUrl.fromLocalFile(
            str(Path(__file__).resolve().parent.parent / "README.md")
        ).toString()
        license_url = QUrl.fromLocalFile(
            str(Path(__file__).resolve().parent.parent / "LICENSE")
        ).toString()
        links = QLabel(
            f"<a href='{readme_url}'>README</a> &nbsp;·&nbsp; "
            f"<a href='{license_url}'>License</a> &nbsp;·&nbsp; "
            f"<a href='{APPLET_REPOSITORY}'>Repository</a>"
        )
        links.setOpenExternalLinks(True)
        links.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(links)
        about_layout.addStretch(1)
        tabs.addTab(about_page, "About")

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

    def _runtime_units_selected(self, checked):
        if checked:
            self.owner.set_unit_files_enabled(False, persist=True, reload=True)
            self._sync_export_mode()

    def _unit_files_selected(self, checked):
        if checked:
            self.owner.set_unit_files_enabled(True, persist=True, reload=True)
            self._sync_export_mode()

    def _sync_export_mode(self):
        unit_files = bool(self.owner.unit_files_enabled)
        for widget in (
            getattr(self, "export_unit_file", None),
            getattr(self, "export_state", None),
            getattr(self, "export_preset", None),
        ):
            if widget is not None:
                widget.setVisible(unit_files)
        for widget in (
            getattr(self, "export_unit", None),
            getattr(self, "export_description", None),
            getattr(self, "export_load", None),
            getattr(self, "export_status", None),
            getattr(self, "export_sub", None),
        ):
            if widget is not None:
                widget.setVisible(not unit_files)

    def _layout_changed(self, text):
        orientation = "vertical" if str(text).lower().startswith("vertical") else "horizontal"
        self.owner.set_details_orientation(orientation, persist=True)

    def _metadata_panel_changed(self, checked):
        self.owner.set_metadata_panel_visible(bool(checked), persist=True)

    def _failed_units_only_changed(self, checked):
        self.owner.set_failed_units_only(bool(checked), persist=True, refilter=True)

    def _export_selected(self):
        selected = []
        if getattr(self, "export_manager", None) is not None and self.export_manager.isChecked():
            selected.append(("manager_scope", "Manager", 90, "left"))
        if self.owner.unit_files_enabled:
            if getattr(self, "export_unit_file", None) is not None and self.export_unit_file.isChecked():
                selected.append(("name", "Unit File", 360, "left"))
            if getattr(self, "export_state", None) is not None and self.export_state.isChecked():
                selected.append(("state", "State", 150, "left"))
            if getattr(self, "export_preset", None) is not None and self.export_preset.isChecked():
                selected.append(("preset", "Preset", 150, "left"))
        else:
            if getattr(self, "export_unit", None) is not None and self.export_unit.isChecked():
                selected.append(("name", "Unit", 210, "left"))
            if getattr(self, "export_description", None) is not None and self.export_description.isChecked():
                selected.append(("description", "Description", 360, "left"))
            if getattr(self, "export_load", None) is not None and self.export_load.isChecked():
                selected.append(("load", "Load", 95, "left"))
            if getattr(self, "export_status", None) is not None and self.export_status.isChecked():
                selected.append(("active", "State", 100, "left"))
            if getattr(self, "export_sub", None) is not None and self.export_sub.isChecked():
                selected.append(("sub", "Sub State", 100, "left"))

        if self.export_metadata.isChecked():
            selected.append(("metadata_details", "Metadata Details", 520, "left"))

        if not selected:
            QMessageBox.information(
                self, "Export", "Select at least one detail to export."
            )
            return

        source_records = self.owner.get_export_records()
        if not source_records:
            QMessageBox.information(
                self, "Export", "There is no collected data to export yet."
            )
            return

        records = []
        for record in source_records:
            item = dict(record)
            item["manager_scope"] = "User" if self.owner.manager_scope == "user" else "System"
            if self.export_metadata.isChecked():
                if self.owner.unit_files_enabled:
                    item["metadata_details"] = _unit_file_metadata_plain_text(record, self.owner.manager_scope)
                else:
                    item["metadata_details"] = _metadata_details_plain_text(
                        str(record.get("name", "")), self.owner.manager_scope
                    )
            records.append(item)

        path = export_records_dialog(
            self, APPLET_NAME, records, columns=selected
        )
        if path is not None:
            self.owner.set_status(f"Exported data to {path}")

def _read_text(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def _format_bytes(value):
    try:
        amount = int(str(value).strip())
    except (TypeError, ValueError):
        return str(value or "-")
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    number = float(amount)
    for unit in units:
        if abs(number) < 1024.0 or unit == units[-1]:
            return f"{number:.1f} {unit}" if unit != "B" else f"{int(number)} B"
        number /= 1024.0
    return f"{amount} B"


def _systemd_show(service_name, manager_scope="system"):
    values, _result = _systemd_show_properties(
        service_name, ("ControlGroup", "MainPID"), timeout=8, manager_scope=manager_scope
    )
    return values


def _cgroup_snapshot(unit_name, manager_scope="system"):
    """Return read-only cgroup v2 details for a selected systemd unit."""
    values = _systemd_show(unit_name, manager_scope)
    control_group = values.get("ControlGroup", "")
    main_pid = values.get("MainPID", "0")
    details = [("Control Group", control_group or "Not active"), ("Main PID", main_pid or "0")]
    if not control_group:
        return details, []

    cgroup_root = Path("/sys/fs/cgroup")
    is_v2 = (cgroup_root / "cgroup.controllers").is_file()
    details.append(("Hierarchy", "cgroup v2" if is_v2 else "legacy / mixed cgroup"))
    root = cgroup_root / control_group.lstrip("/")
    if not root.is_dir():
        details.append(("Cgroup Path", f"{root} (not accessible)"))
        return details, []

    details.append(("Cgroup Path", str(root)))
    for label, filename in (
        ("Cgroup Type", "cgroup.type"),
        ("Controllers", "cgroup.controllers"),
        ("Delegated Controllers", "cgroup.subtree_control"),
        ("Memory Current", "memory.current"),
        ("Memory Max", "memory.max"),
        ("PIDs Current", "pids.current"),
        ("PIDs Max", "pids.max"),
        ("CPU Weight", "cpu.weight"),
        ("I/O Weight", "io.weight"),
    ):
        value = _read_text(root / filename)
        if not value:
            continue
        if filename.startswith("memory.") and value != "max":
            value = _format_bytes(value)
        details.append((label, value))

    cpu_stat = _read_text(root / "cpu.stat")
    if cpu_stat:
        for line in cpu_stat.splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2:
                label = parts[0].replace("_", " ").title()
                details.append((f"CPU {label}", parts[1]))

    processes = []
    for raw_pid in _read_text(root / "cgroup.procs").splitlines()[:100]:
        raw_pid = raw_pid.strip()
        if not raw_pid.isdigit():
            continue
        name = _read_text(Path("/proc") / raw_pid / "comm") or "-"
        processes.append((raw_pid, name))
    return details, processes


def _metadata_details_plain_text(unit_name, manager_scope="system"):
    """Return the same operational metadata sections used by Record Details."""
    if not unit_name:
        return ""

    lines = [f"Unit Status: {unit_name}", f"Manager: {'User' if str(manager_scope).lower() == 'user' else 'System'}", "", "--- systemctl status ---"]
    try:
        status = subprocess.run(
            _systemctl_unit_command(manager_scope, "status", unit_name, "--no-pager", "--lines=0"),
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        status_text = status.stdout or status.stderr or "No unit status output."
        lines.append(status_text.rstrip())
    except FileNotFoundError as exc:
        lines.append(f"Required system command is unavailable: {exc}")
    except subprocess.TimeoutExpired:
        lines.append("Unit status inspection timed out.")
    except Exception as exc:
        lines.append(f"Error retrieving unit status: {exc}")

    lines.extend(["", "--- Control Group / cgroup ---"])
    try:
        cgroup_details, cgroup_processes = _cgroup_snapshot(unit_name, manager_scope)
        for key, value in cgroup_details:
            lines.append(f"{key}: {value}")
        if cgroup_processes:
            lines.extend(["", "Processes in Cgroup:"])
            for pid, name in cgroup_processes:
                lines.append(f"  {pid}  {name}")
            if len(cgroup_processes) >= 100:
                lines.append("  ... truncated to 100 processes")
    except subprocess.TimeoutExpired:
        lines.append("Cgroup details timed out while querying systemd.")
    except Exception as exc:
        lines.append(f"Cgroup details unavailable: {exc}")

    try:
        journal = subprocess.run(
            _journal_unit_command(manager_scope, unit_name),
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        if journal.returncode == 0 and journal.stdout.strip():
            lines.extend(["", "--- Recent Journal Logs ---", journal.stdout.rstrip()])
    except FileNotFoundError as exc:
        lines.extend(["", "--- Recent Journal Logs ---", f"Required system command is unavailable: {exc}"])
    except subprocess.TimeoutExpired:
        lines.extend(["", "--- Recent Journal Logs ---", "Journal inspection timed out."])
    except Exception as exc:
        lines.extend(["", "--- Recent Journal Logs ---", f"Journal details unavailable: {exc}"])

    return "\n".join(lines).rstrip()


def _unit_file_metadata_plain_text(record, manager_scope="system"):
    """Return read-only metadata for one list-unit-files record."""
    record = dict(record or {})
    unit_name = str(record.get("name", "")).strip()
    lines = [
        f"Unit File: {unit_name or '-'}",
        f"Manager: {'User' if str(manager_scope).lower() == 'user' else 'System'}",
        f"State: {record.get('state', '') or '-'}",
        f"Preset: {record.get('preset', '') or '-'}",
    ]
    if not unit_name:
        return "\n".join(lines)

    properties = (
        "Id", "LoadState", "ActiveState", "SubState", "FragmentPath",
        "SourcePath", "DropInPaths", "UnitFileState", "UnitFilePreset",
    )
    try:
        values, result = _systemd_show_properties(unit_name, properties, timeout=8, manager_scope=manager_scope)
    except FileNotFoundError as exc:
        return "\n".join(lines + ["", "--- systemctl show ---", f"Required system command is unavailable: {exc}"])
    except subprocess.TimeoutExpired:
        return "\n".join(lines + ["", "--- systemctl show ---", "Unit-file metadata query timed out."])
    except Exception as exc:
        return "\n".join(lines + ["", "--- systemctl show ---", f"Unit-file metadata unavailable: {exc}"])

    lines.extend(["", "--- systemctl show ---"])
    labels = (
        ("Id", "Reported ID"),
        ("LoadState", "Load State"),
        ("ActiveState", "Active State"),
        ("SubState", "Sub State"),
        ("FragmentPath", "Fragment Path"),
        ("SourcePath", "Source Path"),
        ("DropInPaths", "Drop-In Paths"),
        ("UnitFileState", "Unit File State"),
        ("UnitFilePreset", "Unit File Preset"),
    )
    for key, label in labels:
        lines.append(f"{label}: {values.get(key, '') or '-'}")
    if result.returncode != 0 and result.stderr.strip():
        lines.extend(["", "Query Status: " + result.stderr.strip()])
    return "\n".join(lines).rstrip()


class SystemdTab(BaseInspectorTab):
    UNIT_TYPES = (
        ("All Types", ""),
        ("Automounts", "automount"),
        ("Devices", "device"),
        ("Mounts", "mount"),
        ("Paths", "path"),
        ("Scopes", "scope"),
        ("Services", "service"),
        ("Slices", "slice"),
        ("Sockets", "socket"),
        ("Swaps", "swap"),
        ("Targets", "target"),
        ("Timers", "timer"),
    )

    def __init__(self, parent=None):
        columns = [
            ("name", "Unit", 210, "left"),
            ("description", "Description", 360, "left"),
            ("load", "Load", 95, "left"),
            ("active", "State", 100, "left"),
            ("sub", "Sub State", 100, "left"),
        ]
        super().__init__("System Units", columns, ["All States"], parent)
        self.export_title = APPLET_NAME
        self.unit_files_enabled = False
        self.failed_units_only = False
        self.manager_scope = "system"
        self._load_manager_scope()
        self.unit_file_data = []
        self._unit_file_sort_reverse = {}
        self._unit_file_columns = [
            ("name", "Unit File", 390, "left"),
            ("state", "State", 170, "left"),
            ("preset", "Preset", 170, "left"),
        ]

        self.category_label.setText("State:")
        self.category_dropdown.clear()
        self.category_dropdown.addItem("All States", "")
        unit_header = self.table.horizontalHeaderItem(0)
        if unit_header is not None:
            unit_header.setTextAlignment(
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
            )

        # Journal Inspector 0.0.4-r1 established the safe alternate-inventory
        # pattern: never recolumnize the normal table. Unit Files therefore owns
        # an independent table in a stacked inventory.
        self.inventory_stack = QStackedWidget()
        self.table.setParent(self.inventory_stack)
        self.inventory_stack.addWidget(self.table)

        self.unit_file_table = QTableWidget(0, len(self._unit_file_columns))
        self.unit_file_table.setHorizontalHeaderLabels(
            [column[1] for column in self._unit_file_columns]
        )
        self.unit_file_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.unit_file_table.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection
        )
        self.unit_file_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self.unit_file_table.setAlternatingRowColors(True)
        self.unit_file_table.verticalHeader().setVisible(False)
        for index, (_column_id, _label, width, _alignment) in enumerate(self._unit_file_columns):
            self.unit_file_table.setColumnWidth(index, width)
        self.unit_file_table.itemSelectionChanged.connect(self._on_unit_file_select)
        self.unit_file_table.horizontalHeader().sectionClicked.connect(
            self._sort_unit_files_by_section
        )
        self.inventory_stack.addWidget(self.unit_file_table)
        self.splitter.insertWidget(0, self.inventory_stack)
        self.splitter.setSizes([480, 700])

        self.unit_file_column_visibility = ColumnVisibilityController(
            self.unit_file_table, self._unit_file_columns, self.set_status
        )
        self.unit_file_column_visibility.set_changed_callback(
            self._save_unit_file_hidden_columns
        )
        self._load_unit_file_hidden_columns()

        # Manager scope is fundamental acquisition context, but is kept with
        # Search/State in the filter row so the top action bar remains compact.
        filter_layout = None
        root_layout = self.layout()
        if root_layout is not None:
            for index in range(root_layout.count()):
                candidate = root_layout.itemAt(index).layout()
                if candidate is not None and candidate.indexOf(self.category_dropdown) >= 0:
                    filter_layout = candidate
                    break
        if filter_layout is not None:
            insert_at = filter_layout.indexOf(self.category_dropdown) + 1
            self.manager_scope_label = QLabel("Manager:")
            self.manager_scope_label.setStyleSheet("font-weight: 600;")
            self.manager_system_radio = QRadioButton("System")
            self.manager_user_radio = QRadioButton("User")
            self.manager_scope_group = QButtonGroup(self)
            self.manager_scope_group.setExclusive(True)
            self.manager_scope_group.addButton(self.manager_system_radio)
            self.manager_scope_group.addButton(self.manager_user_radio)
            self.manager_system_radio.setChecked(self.manager_scope == "system")
            self.manager_user_radio.setChecked(self.manager_scope == "user")
            self.manager_system_radio.toggled.connect(
                lambda checked: checked and self.set_manager_scope("system", persist=True, reload=True)
            )
            self.manager_user_radio.toggled.connect(
                lambda checked: checked and self.set_manager_scope("user", persist=True, reload=True)
            )
            filter_layout.insertSpacing(insert_at, 10)
            insert_at += 1
            filter_layout.insertWidget(insert_at, self.manager_scope_label)
            insert_at += 1
            filter_layout.insertWidget(insert_at, self.manager_system_radio)
            insert_at += 1
            filter_layout.insertWidget(insert_at, self.manager_user_radio)

        refresh_index = self.dash_layout.indexOf(self.refresh_btn)
        self.unit_type_label = QLabel("Unit Type:")
        self.unit_type_label.setStyleSheet("font-weight: 600;")
        self.dash_layout.insertWidget(refresh_index, self.unit_type_label)
        refresh_index += 1

        self.unit_type_combo = QComboBox()
        for label, unit_type in self.UNIT_TYPES:
            self.unit_type_combo.addItem(label, unit_type)
        self.unit_type_combo.currentIndexChanged.connect(self.load_modules)
        self.dash_layout.insertWidget(refresh_index, self.unit_type_combo)
        refresh_index += 1

        self.unit_details_btn = QPushButton("Unit Details...")
        self.unit_details_btn.setToolTip(
            "Show structured systemd-reported details for the selected unit."
        )
        self.unit_details_btn.clicked.connect(self.show_unit_details)
        self.dash_layout.insertWidget(refresh_index, self.unit_details_btn)

        self.export_btn.hide()
        export_index = self.dash_layout.indexOf(self.export_btn)
        self.options_btn = QPushButton("Options...")
        self.options_btn.clicked.connect(self.show_options)
        self.dash_layout.insertWidget(export_index, self.options_btn)

        self.details_orientation = "horizontal"
        self.metadata_panel_visible = True
        self._load_details_orientation()
        self._load_inventory_mode()
        self._load_failed_units_only()
        self._load_metadata_panel_visibility()
        self._apply_inventory_mode()
        self.set_metadata_panel_visible(self.metadata_panel_visible, persist=False)

        self._shortcut_ack = ""
        self._last_status_text = ""
        self._shortcut_ack_timer = QTimer(self)
        self._shortcut_ack_timer.setSingleShot(True)
        self._shortcut_ack_timer.setInterval(1800)
        self._shortcut_ack_timer.timeout.connect(self._clear_shortcut_ack)

        self._install_shortcuts()
        self.load_modules()

    def show_options(self):
        dialog = SystemdOptionsDialog(self)
        dialog.exec()

    def _load_manager_scope(self):
        settings = QSettings("brunonlinespace", "Systemd Inspector")
        scope = str(settings.value("manager_scope", "system") or "system").lower()
        self.manager_scope = scope if scope in {"system", "user"} else "system"

    def set_manager_scope(self, scope, *, persist=True, reload=True):
        scope = "user" if str(scope).lower() == "user" else "system"
        changed = scope != self.manager_scope
        self.manager_scope = scope
        if hasattr(self, "manager_system_radio") and scope == "system" and not self.manager_system_radio.isChecked():
            self.manager_system_radio.setChecked(True)
        if hasattr(self, "manager_user_radio") and scope == "user" and not self.manager_user_radio.isChecked():
            self.manager_user_radio.setChecked(True)
        if persist:
            settings = QSettings("brunonlinespace", "Systemd Inspector")
            settings.setValue("manager_scope", scope)
            settings.sync()
        self.clear_info()
        self.modules_data.clear()
        self.unit_file_data.clear()
        self.table.clearSelection()
        self.unit_file_table.clearSelection()
        self.table.setRowCount(0)
        self.unit_file_table.setRowCount(0)
        self.filter_status_lbl.clear()
        if reload and changed:
            self.load_modules()

    def set_status(self, text):
        self._last_status_text = str(text)
        shown = self._last_status_text
        if getattr(self, "_shortcut_ack", ""):
            shown = f"{self._shortcut_ack} · {shown}"
        super().set_status(shown)

    def _ack_shortcut(self, label):
        self._shortcut_ack = f"Shortcut {label}"
        if hasattr(self, "_shortcut_ack_timer"):
            self._shortcut_ack_timer.start()
        base = getattr(self, "_last_status_text", "") or "Accepted."
        super().set_status(f"{self._shortcut_ack} · {base}")

    def _clear_shortcut_ack(self):
        self._shortcut_ack = ""
        super().set_status(getattr(self, "_last_status_text", ""))

    def _install_shortcuts(self):
        self._metadata_shortcut = QShortcut(QKeySequence("F3"), self)
        self._metadata_shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        self._metadata_shortcut.activated.connect(self._shortcut_toggle_metadata)

        self._layout_shortcut = QShortcut(QKeySequence("Ctrl+L"), self)
        self._layout_shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        self._layout_shortcut.activated.connect(self._shortcut_toggle_layout)

        self._unit_files_shortcut = QShortcut(QKeySequence("Ctrl+Shift+I"), self)
        self._unit_files_shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        self._unit_files_shortcut.activated.connect(self._shortcut_toggle_unit_files)

        self._unit_details_shortcut = QShortcut(QKeySequence("F4"), self)
        self._unit_details_shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        self._unit_details_shortcut.activated.connect(self._shortcut_open_unit_details)

        self._refresh_shortcut = QShortcut(QKeySequence("Shift+F5"), self)
        self._refresh_shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        self._refresh_shortcut.activated.connect(self._shortcut_refresh)

        self._manager_shortcut = QShortcut(QKeySequence("Ctrl+M"), self)
        self._manager_shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        self._manager_shortcut.activated.connect(self._shortcut_toggle_manager)

        self._failed_units_shortcut = QShortcut(QKeySequence("Ctrl+F"), self)
        self._failed_units_shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        self._failed_units_shortcut.activated.connect(self._shortcut_toggle_failed_units_only)
        self._failed_units_shortcut.setEnabled(not self.unit_files_enabled)

        self._options_shortcut = QShortcut(QKeySequence("Ctrl+/"), self)
        self._options_shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        self._options_shortcut.activated.connect(self._shortcut_open_options)

    def _shortcut_toggle_metadata(self):
        self._ack_shortcut("F3")
        self.toggle_metadata_panel()

    def _shortcut_toggle_layout(self):
        self._ack_shortcut("Ctrl+L")
        self.toggle_details_orientation()

    def _shortcut_toggle_unit_files(self):
        self._ack_shortcut("Ctrl+Shift+I")
        self.toggle_unit_files_mode()

    def _shortcut_open_unit_details(self):
        self._ack_shortcut("F4")
        self.show_unit_details()

    def _shortcut_refresh(self):
        self._ack_shortcut("Shift+F5")
        self.load_modules()

    def _shortcut_toggle_manager(self):
        self._ack_shortcut("Ctrl+M")
        target = "user" if self.manager_scope == "system" else "system"
        self.set_manager_scope(target, persist=True, reload=True)

    def _shortcut_toggle_failed_units_only(self):
        if self.unit_files_enabled:
            return
        self._ack_shortcut("Ctrl+F")
        self.set_failed_units_only(
            not self.failed_units_only, persist=True, refilter=True
        )

    def _shortcut_open_options(self):
        self._ack_shortcut("Ctrl+/")
        self.set_status("Opening Options...")
        self.show_options()

    def _load_metadata_panel_visibility(self):
        settings = QSettings("brunonlinespace", "Systemd Inspector")
        value = settings.value("metadata_panel_visible", True)
        if isinstance(value, str):
            self.metadata_panel_visible = value.strip().lower() not in {"0", "false", "no", "off"}
        else:
            self.metadata_panel_visible = bool(value)

    def set_metadata_panel_visible(self, visible, *, persist=True):
        visible = bool(visible)
        self.metadata_panel_visible = visible
        details_panel = self.splitter.widget(1)
        if details_panel is not None:
            details_panel.setVisible(visible)
        if visible:
            self.set_details_orientation(self.details_orientation, persist=False)
        if persist:
            settings = QSettings("brunonlinespace", "Systemd Inspector")
            settings.setValue("metadata_panel_visible", visible)
            settings.sync()

    def toggle_metadata_panel(self):
        self.set_metadata_panel_visible(not self.metadata_panel_visible, persist=True)
        self.set_status(
            "Metadata Details panel shown."
            if self.metadata_panel_visible
            else "Metadata Details panel hidden."
        )

    def toggle_details_orientation(self):
        orientation = "vertical" if self.details_orientation == "horizontal" else "horizontal"
        self.set_details_orientation(orientation, persist=True)
        self.set_status(f"Metadata Details layout set to {orientation.title()}.")

    def toggle_unit_files_mode(self):
        self.set_unit_files_enabled(
            not self.unit_files_enabled, persist=True, reload=True
        )
        self.set_status(
            "Inventory: Unit Files."
            if self.unit_files_enabled
            else "Inventory: Runtime Units."
        )

    def _load_details_orientation(self):
        settings = QSettings("brunonlinespace", "Systemd Inspector")
        orientation = str(settings.value("details_orientation", "horizontal") or "horizontal").lower()
        if orientation not in {"horizontal", "vertical"}:
            orientation = "horizontal"
        self.set_details_orientation(orientation, persist=False)

    def set_details_orientation(self, orientation, *, persist=True):
        orientation = str(orientation or "horizontal").lower()
        if orientation not in {"horizontal", "vertical"}:
            orientation = "horizontal"
        self.details_orientation = orientation

        details_panel = self.splitter.widget(1)
        details_layout = details_panel.layout() if details_panel is not None else None
        if orientation == "vertical":
            self.splitter.setOrientation(Qt.Orientation.Vertical)
            if details_layout is not None:
                details_layout.setContentsMargins(0, 8, 0, 0)
            self.splitter.setSizes([430, 330])
        else:
            self.splitter.setOrientation(Qt.Orientation.Horizontal)
            if details_layout is not None:
                details_layout.setContentsMargins(8, 0, 0, 0)
            self.splitter.setSizes([480, 700])

        if persist:
            settings = QSettings("brunonlinespace", "Systemd Inspector")
            settings.setValue("details_orientation", orientation)
            settings.sync()

    def _load_inventory_mode(self):
        settings = QSettings("brunonlinespace", "Systemd Inspector")
        value = settings.value("unit_files_enabled", False)
        if isinstance(value, str):
            self.unit_files_enabled = value.strip().lower() in {"1", "true", "yes", "on"}
        else:
            self.unit_files_enabled = bool(value)

    def set_unit_files_enabled(self, enabled, *, persist=True, reload=True):
        enabled = bool(enabled)
        changed = enabled != self.unit_files_enabled
        self.unit_files_enabled = enabled
        if persist:
            settings = QSettings("brunonlinespace", "Systemd Inspector")
            settings.setValue("unit_files_enabled", enabled)
            settings.sync()
        self._apply_inventory_mode()
        if reload and (changed or not self.get_export_records()):
            self.load_modules()

    def _load_failed_units_only(self):
        settings = QSettings("brunonlinespace", "Systemd Inspector")
        value = settings.value("failed_units_only", False)
        if isinstance(value, str):
            self.failed_units_only = value.strip().lower() in {"1", "true", "yes", "on"}
        else:
            self.failed_units_only = bool(value)

    def set_failed_units_only(self, enabled, *, persist=True, refilter=True):
        enabled = bool(enabled)
        self.failed_units_only = enabled
        if persist:
            settings = QSettings("brunonlinespace", "Systemd Inspector")
            settings.setValue("failed_units_only", enabled)
            settings.sync()
        if refilter and not self.unit_files_enabled:
            self.filter_modules()
            self.set_status(
                "Failed units only enabled." if enabled else "Failed units only disabled."
            )
        elif self.unit_files_enabled:
            self.set_status(
                "Failed units only preference retained; it applies to Runtime Units."
            )

    def _apply_inventory_mode(self):
        self.clear_info()
        self.table.clearSelection()
        self.unit_file_table.clearSelection()
        if self.unit_files_enabled:
            self.inventory_stack.setCurrentWidget(self.unit_file_table)
            self.category_label.setText("State:")
            self.search_entry.setPlaceholderText("Search unit files...")
        else:
            self.inventory_stack.setCurrentWidget(self.table)
            self.category_label.setText("State:")
            self.search_entry.setPlaceholderText("Search units...")
        if hasattr(self, "_failed_units_shortcut"):
            self._failed_units_shortcut.setEnabled(not self.unit_files_enabled)
        self._rebuild_state_filter()

    def _load_unit_file_hidden_columns(self):
        settings = QSettings("brunonlinespace", "Systemd Inspector")
        value = settings.value("unit_files_hidden_columns", [])
        if value is None:
            hidden = []
        elif isinstance(value, str):
            hidden = [value] if value else []
        else:
            try:
                hidden = list(value)
            except TypeError:
                hidden = []
        self.unit_file_column_visibility.apply_hidden(hidden)

    def _save_unit_file_hidden_columns(self, hidden):
        settings = QSettings("brunonlinespace", "Systemd Inspector")
        settings.setValue("unit_files_hidden_columns", list(hidden or []))
        settings.sync()

    def current_record(self):
        table = self.unit_file_table if self.unit_files_enabled else self.table
        row = table.currentRow()
        if row < 0:
            return None
        item = table.item(row, 0)
        if item is None:
            return None
        return item.data(Qt.ItemDataRole.UserRole)

    def get_export_records(self):
        if self.unit_files_enabled:
            return list(self.unit_file_data)
        return list(self.modules_data)

    def show_unit_details(self):
        record = self.current_record()
        if not record:
            self.set_status("Select a unit first.")
            QMessageBox.information(
                self,
                "Unit Details",
                "Select a unit in the table first.",
            )
            return
        try:
            dialog = UnitDetailsDialog(self, record["name"], self.manager_scope)
            dialog.exec()
        except Exception as exc:
            self.show_error(
                "Unit Details",
                f"Could not open details for {record.get('name', 'the selected unit')}:\n{exc}",
            )

    def load_modules(self, *_):
        if self.unit_files_enabled:
            return self._load_unit_files()
        return self._load_runtime_units()

    def _load_runtime_units(self):
        self.modules_data.clear()
        unit_type = str(self.unit_type_combo.currentData() or "")
        manager_label = "User" if self.manager_scope == "user" else "System"
        command = _systemctl_command(self.manager_scope, "list-units")
        if unit_type:
            command.append(f"--type={unit_type}")
        command.extend(["--all", "--no-legend", "--no-pager"])
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=12,
            )
        except FileNotFoundError:
            self.clear_info()
            self.table.setRowCount(0)
            self._rebuild_state_filter()
            self.set_status("systemctl is not available on this system.")
            return
        except subprocess.TimeoutExpired:
            self.clear_info()
            self.table.setRowCount(0)
            self._rebuild_state_filter()
            scope = self.unit_type_combo.currentText() if unit_type else "Units"
            self.set_status(f"Timed out while reading {manager_label} {scope}.")
            return
        except Exception as exc:
            self.clear_info()
            self.table.setRowCount(0)
            self._rebuild_state_filter()
            scope = self.unit_type_combo.currentText() if unit_type else "Units"
            self.set_status(f"Error reading {manager_label} {scope}: {exc}")
            return

        if result.returncode != 0 and not result.stdout:
            self.clear_info()
            self.table.setRowCount(0)
            self._rebuild_state_filter()
            message = (result.stderr or "systemctl returned an error.").strip()
            scope = self.unit_type_combo.currentText() if unit_type else "Units"
            self.set_status(f"Error reading {manager_label} {scope}: {message}")
            return

        for line in result.stdout.splitlines():
            parts = line.split(None, 4)
            if len(parts) < 4:
                continue
            self.modules_data.append({
                "name": parts[0],
                "load": parts[1],
                "active": parts[2],
                "sub": parts[3],
                "description": parts[4] if len(parts) > 4 else "",
            })

        if not unit_type:
            self.modules_data.sort(
                key=lambda record: str(record.get("name", "")).casefold()
            )

        self._rebuild_state_filter()
        unit_type_label = self.unit_type_combo.currentText() or "Units"
        if unit_type:
            self.stats_label.setText(
                f"{manager_label} {unit_type_label}: {len(self.modules_data)}"
            )
        else:
            self.stats_label.setText(
                f"{manager_label} Units: {len(self.modules_data)}"
            )
        self.filter_modules()
        if unit_type:
            self.set_status(f"Refreshed {manager_label} {unit_type_label}.")
        else:
            self.set_status(f"Refreshed {manager_label} Units.")

    def _load_unit_files(self):
        self.unit_file_data.clear()
        unit_type = str(self.unit_type_combo.currentData() or "")
        manager_label = "User" if self.manager_scope == "user" else "System"
        command = _systemctl_command(self.manager_scope, "list-unit-files")
        if unit_type:
            command.append(f"--type={unit_type}")
        command.extend(["--all", "--no-legend", "--no-pager"])
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=12,
            )
        except FileNotFoundError:
            self.clear_info()
            self.unit_file_table.setRowCount(0)
            self._rebuild_state_filter()
            self.set_status("systemctl is not available on this system.")
            return
        except subprocess.TimeoutExpired:
            self.clear_info()
            self.unit_file_table.setRowCount(0)
            self._rebuild_state_filter()
            scope = f"{unit_type.title()} Unit Files" if unit_type else "Unit Files"
            self.set_status(f"Timed out while reading {manager_label} {scope}.")
            return
        except Exception as exc:
            self.clear_info()
            self.unit_file_table.setRowCount(0)
            self._rebuild_state_filter()
            scope = f"{unit_type.title()} Unit Files" if unit_type else "Unit Files"
            self.set_status(f"Error reading {manager_label} {scope}: {exc}")
            return

        if result.returncode != 0 and not result.stdout:
            self.clear_info()
            self.unit_file_table.setRowCount(0)
            self._rebuild_state_filter()
            message = (result.stderr or "systemctl returned an error.").strip()
            scope = f"{unit_type.title()} Unit Files" if unit_type else "Unit Files"
            self.set_status(f"Error reading {manager_label} {scope}: {message}")
            return

        for line in result.stdout.splitlines():
            parts = line.split(None, 2)
            if len(parts) < 2:
                continue
            self.unit_file_data.append({
                "name": parts[0],
                "state": parts[1],
                "preset": parts[2] if len(parts) > 2 else "",
            })
        self.unit_file_data.sort(
            key=lambda record: str(record.get("name", "")).casefold()
        )

        self._rebuild_state_filter()
        if unit_type:
            unit_type_name = unit_type.title()
            self.stats_label.setText(
                f"{manager_label} {unit_type_name} Unit Files: {len(self.unit_file_data)}"
            )
        else:
            self.stats_label.setText(
                f"{manager_label} Unit Files: {len(self.unit_file_data)}"
            )
        self.filter_modules()
        if unit_type:
            self.set_status(f"Refreshed {manager_label} {unit_type.title()} Unit Files.")
        else:
            self.set_status(f"Refreshed {manager_label} Unit Files.")

    def _rebuild_state_filter(self):
        current_value = str(self.category_dropdown.currentData() or "")
        if self.unit_files_enabled:
            label = "All States"
            values = []
            for record in self.unit_file_data:
                state = str(record.get("state", ""))
                if state and state not in values:
                    values.append(state)
        else:
            label = "All States"
            values = []
            for record in self.modules_data:
                state = str(record.get("active", ""))
                if state and state not in values:
                    values.append(state)
        values.sort(key=str.casefold)
        self.category_dropdown.blockSignals(True)
        self.category_dropdown.clear()
        self.category_dropdown.addItem(label, "")
        for value in values:
            self.category_dropdown.addItem(value, value)
        restore_index = self.category_dropdown.findData(current_value)
        self.category_dropdown.setCurrentIndex(restore_index if restore_index >= 0 else 0)
        self.category_dropdown.blockSignals(False)

    def filter_modules(self, *_):
        if self.unit_files_enabled:
            return self._filter_unit_files()
        return self._filter_runtime_units()

    def _filter_runtime_units(self):
        query = self.search_entry.text().strip().lower()
        selected_active = str(self.category_dropdown.currentData() or "")
        matches = []
        for record in self.modules_data:
            active_state = str(record.get("active", ""))
            match_active = not selected_active or active_state == selected_active
            match_failed = not self.failed_units_only or active_state == "failed"
            match_query = not query or any(
                query in str(value).lower() for value in record.values()
            )
            if match_active and match_failed and match_query:
                matches.append(record)

        blocked = self.table.blockSignals(True)
        try:
            self.clear_info()
            self.table.clearSelection()
            self.table.setSortingEnabled(False)
            self.table.setRowCount(len(matches))
            for row, record in enumerate(matches):
                for column_index, (column_id, _label, _width, alignment) in enumerate(self.columns):
                    value = record.get(column_id, "")
                    display = str(value)
                    item = QTableWidgetItem(display)
                    if column_index == 0:
                        item.setData(Qt.ItemDataRole.UserRole, record)
                    item.setTextAlignment(
                        (Qt.AlignmentFlag.AlignRight if alignment == "right" else Qt.AlignmentFlag.AlignLeft)
                        | Qt.AlignmentFlag.AlignVCenter
                    )
                    self.style_table_item(item, column_id, record)
                    self.table.setItem(row, column_index, item)
            if matches:
                self.table.setCurrentCell(0, 0)
                self.table.selectRow(0)
            else:
                self.table.setCurrentCell(-1, -1)
        finally:
            self.table.blockSignals(blocked)

        self.export_btn.setEnabled(bool(self.modules_data))
        if query or selected_active or self.failed_units_only:
            prefix = "Failed only · " if self.failed_units_only else ""
            self.filter_status_lbl.setText(
                f"({prefix}Showing {len(matches)} of {len(self.modules_data)} items)"
            )
        else:
            self.filter_status_lbl.clear()
        if matches:
            self.on_module_select()
        elif self.failed_units_only and not query and not selected_active:
            self.set_status("No failed runtime units were reported.")
        elif self.failed_units_only:
            self.set_status("No failed runtime units match the current filters.")
        else:
            self.set_status("No systemd units match the current filter.")

    def _filter_unit_files(self):
        query = self.search_entry.text().strip().lower()
        selected_state = str(self.category_dropdown.currentData() or "")
        matches = []
        for record in self.unit_file_data:
            match_state = not selected_state or str(record.get("state", "")) == selected_state
            match_query = not query or any(
                query in str(value).lower() for value in record.values()
            )
            if match_state and match_query:
                matches.append(record)

        blocked = self.unit_file_table.blockSignals(True)
        try:
            self.clear_info()
            self.unit_file_table.clearSelection()
            self.unit_file_table.setSortingEnabled(False)
            self.unit_file_table.setRowCount(len(matches))
            for row, record in enumerate(matches):
                for column_index, (column_id, _label, _width, alignment) in enumerate(self._unit_file_columns):
                    item = QTableWidgetItem(str(record.get(column_id, "")))
                    if column_index == 0:
                        item.setData(Qt.ItemDataRole.UserRole, record)
                    item.setTextAlignment(
                        (Qt.AlignmentFlag.AlignRight if alignment == "right" else Qt.AlignmentFlag.AlignLeft)
                        | Qt.AlignmentFlag.AlignVCenter
                    )
                    self.unit_file_table.setItem(row, column_index, item)
            if matches:
                self.unit_file_table.setCurrentCell(0, 0)
                self.unit_file_table.selectRow(0)
            else:
                self.unit_file_table.setCurrentCell(-1, -1)
        finally:
            self.unit_file_table.blockSignals(blocked)

        self.export_btn.setEnabled(bool(self.unit_file_data))
        if query or selected_state:
            self.filter_status_lbl.setText(
                f"(Showing {len(matches)} of {len(self.unit_file_data)} items)"
            )
        else:
            self.filter_status_lbl.clear()
        if matches:
            self._on_unit_file_select()
        else:
            self.set_status("No systemd unit files match the current filter.")

    def _sort_unit_files_by_section(self, section):
        if not (0 <= section < len(self._unit_file_columns)):
            return
        self._sort_unit_files_by(self._unit_file_columns[section][0])

    def _sort_unit_files_by(self, column_id):
        reverse = self._unit_file_sort_reverse.get(column_id, False)
        self.unit_file_data.sort(
            key=lambda item: str(item.get(column_id, "")).casefold(),
            reverse=reverse,
        )
        self._unit_file_sort_reverse[column_id] = not reverse
        self.filter_modules()

    def _on_unit_file_select(self):
        if not self.unit_files_enabled:
            return
        record = self.current_record()
        if not record:
            return
        self.clear_info()
        self.info_text.setPlainText(_unit_file_metadata_plain_text(record, self.manager_scope))
        cursor = self.info_text.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.Start)
        self.info_text.setTextCursor(cursor)
        self.info_text.ensureCursorVisible()
        self.set_status(f"Inspecting {'User' if self.manager_scope == 'user' else 'System'} unit file [{record.get('name', '')}].")

    def on_module_select(self):
        if self.unit_files_enabled:
            return self._on_unit_file_select()
        record = self.current_record()
        if not record:
            return

        unit_name = record["name"]
        self.clear_info()
        self.append_info(f"Unit Status: {unit_name}\n", "heading")
        self.append_key_value("Manager", "User" if self.manager_scope == "user" else "System")
        self.append_info("\n", "value")

        try:
            self.append_info("--- systemctl status ---\n", "key")
            status = subprocess.run(
                _systemctl_unit_command(self.manager_scope, "status", unit_name, "--no-pager", "--lines=0"),
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            status_text = status.stdout or status.stderr or "No unit status output."
            self.append_info(status_text.rstrip() + "\n", "value")

            self.append_info("\n--- Control Group / cgroup ---\n", "key")
            try:
                cgroup_details, cgroup_processes = _cgroup_snapshot(unit_name, self.manager_scope)
                for key, value in cgroup_details:
                    self.append_key_value(key, value)
                if cgroup_processes:
                    self.append_info("\nProcesses in Cgroup:\n", "key")
                    for pid, name in cgroup_processes:
                        self.append_info(f"  {pid}  {name}\n", "value")
                    if len(cgroup_processes) >= 100:
                        self.append_info("  ... truncated to 100 processes\n", "value")
            except subprocess.TimeoutExpired:
                self.append_info("Cgroup details timed out while querying systemd.\n", "value")
            except Exception as exc:
                self.append_info(f"Cgroup details unavailable: {exc}\n", "value")

            journal = subprocess.run(
                _journal_unit_command(self.manager_scope, unit_name),
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            if journal.returncode == 0 and journal.stdout.strip():
                self.append_info("\n--- Recent Journal Logs ---\n", "key")
                self.append_info(journal.stdout, "value")

            self.set_status(f"Inspecting {'User' if self.manager_scope == 'user' else 'System'} unit [{unit_name}].")
        except FileNotFoundError as exc:
            self.append_info(f"Required system command is unavailable: {exc}\n")
            self.set_status(f"Could not inspect unit [{unit_name}].")
        except subprocess.TimeoutExpired:
            self.append_info("Unit inspection timed out.\n")
            self.set_status(f"Timed out inspecting unit [{unit_name}].")
        except Exception as exc:
            self.append_info(f"Error retrieving unit status: {exc}\n")
            self.set_status(f"Could not inspect unit [{unit_name}].")
        finally:
            cursor = self.info_text.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            self.info_text.setTextCursor(cursor)
            self.info_text.ensureCursorVisible()

def create_applet(parent=None):
    return SystemdTab(parent=parent)

def run_standalone():
    import sys
    from pathlib import Path
    from PyQt6.QtGui import QIcon
    from PyQt6.QtWidgets import QApplication, QMainWindow
    from ._support import STANDALONE_STYLESHEET
    app = QApplication(sys.argv)
    app.setApplicationName(APPLET_NAME)
    app.setOrganizationName(APPLET_AUTHOR)
    icon_path = Path(__file__).resolve().parent / "icon.png"
    if icon_path.is_file():
        app.setWindowIcon(QIcon(str(icon_path)))
    app.setStyleSheet(STANDALONE_STYLESHEET)
    window = QMainWindow()
    if icon_path.is_file():
        window.setWindowIcon(QIcon(str(icon_path)))
    window.setWindowTitle(f"{APPLET_NAME} {APPLET_VERSION} — LinSpectacles Applet")
    window.resize(1200, 780)
    window.setCentralWidget(create_applet())
    window.show()
    return app.exec()
