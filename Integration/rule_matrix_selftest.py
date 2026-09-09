#!/usr/bin/env python3
"""Design-level regression checks for conservative the current RCInjectAnalysis rules.

This mirrors intended classification/unknown-state semantics. It is not a
substitute for compiling/running the Objective-C scanner in the RootHide
blacklist Manager in a supported RootHide environment.
"""

def blacklist_residues(appconfig, installed_ids):
    out = []
    for key, value in appconfig.items():
        if not isinstance(key, str) or not key:
            continue
        if not bool(value):
            continue
        if key in installed_ids:
            continue
        out.append(key)
    return sorted(out)


def coverage(bundle_ids, installed_ids):
    installed, absent = [], []
    for bid in bundle_ids:
        if not bid:
            continue
        (installed if bid in installed_ids else absent).append(bid)
    return installed, absent


def bounded_evidence_walk(total_entries, limit):
    if limit <= 0:
        return total_entries, False
    visited = min(total_entries, limit)
    return visited, total_entries > limit



def budget_stop(total_elapsed, app_elapsed, entries, entry_limit=50000, per_app_limit=1.5, global_limit=12.0):
    if total_elapsed >= global_limit:
        return "global-time-skip"
    if app_elapsed >= per_app_limit:
        return "per-app-time"
    if entry_limit > 0 and entries >= entry_limit:
        return "entry-limit"
    return "continue"

def root_hide_config_permits(match_count, blacklist_supported, blacklist_known, blacklisted):
    return bool(match_count) and blacklist_supported and blacklist_known and not blacklisted


def embedded_display_state(global_available, attempted, truncated, records):
    if not global_available:
        return "unavailable"
    if not attempted:
        return "not_scanned"
    if truncated:
        return "partial"
    return "evidence" if records else "none"


def mixed_source(match_count, blacklist_supported, blacklist_known, blacklisted, active_embedded):
    return root_hide_config_permits(match_count, blacklist_supported, blacklist_known, blacklisted) and active_embedded > 0


def app_injection_visible(dpkg_owned_tweaks, trollfools_records):
    return dpkg_owned_tweaks > 0 or trollfools_records > 0


def trollfools_plugin_count(load_paths):
    return len({path for path in load_paths if path})


def split_executable_targets(filter_executables, installed_app_executables, known_system_executables):
    installed, system, unresolved = [], [], []
    for name in filter_executables:
        if name in installed_app_executables:
            installed.append(name)
        elif name in known_system_executables:
            system.append(name)
        else:
            unresolved.append(name)
    return installed, system, unresolved


def system_injection_target(system_executables, unregistered_bundle_ids):
    if any(bool(name) for name in system_executables):
        return True
    known_system_bundles = {"com.apple.springboard", "com.apple.backboardd"}
    return any(isinstance(bid, str) and bid.lower() in known_system_bundles for bid in unregistered_bundle_ids)


def main():
    installed = {"com.xingin.xhs", "com.tencent.xin"}
    appconfig = {
        "com.xingin.xhs": True,
        "com.old.removed": True,
        "com.old.false": False,
        "": True,
    }
    assert blacklist_residues(appconfig, installed) == ["com.old.removed"]

    live, absent = coverage(["com.xingin.xhs", "com.spotify.client"], installed)
    assert live == ["com.xingin.xhs"] and absent == ["com.spotify.client"]
    live, absent = coverage(["com.spotify.client"], installed)
    assert live == [] and absent == ["com.spotify.client"]

    visited, truncated = bounded_evidence_walk(50000, 50000)
    assert visited == 50000 and truncated is False
    visited, truncated = bounded_evidence_walk(50001, 50000)
    assert visited == 50000 and truncated is True

    assert budget_stop(12.0, 0.0, 0) == "global-time-skip"
    assert budget_stop(3.0, 1.5, 100) == "per-app-time"
    assert budget_stop(3.0, 0.3, 50000) == "entry-limit"
    assert budget_stop(3.0, 0.3, 100) == "continue"

    assert root_hide_config_permits(1, True, True, False) is True
    assert root_hide_config_permits(1, True, True, True) is False
    assert root_hide_config_permits(1, False, False, False) is False
    assert root_hide_config_permits(1, True, False, False) is False

    assert embedded_display_state(False, False, False, 0) == "unavailable"
    assert embedded_display_state(True, False, False, 0) == "not_scanned"
    assert embedded_display_state(True, True, True, 0) == "partial"
    assert embedded_display_state(True, True, False, 0) == "none"
    assert embedded_display_state(True, True, False, 1) == "evidence"

    assert mixed_source(1, True, True, False, 1) is True
    assert mixed_source(1, True, True, True, 1) is False
    assert mixed_source(1, False, False, False, 1) is False
    assert mixed_source(1, True, True, False, 0) is False

    assert app_injection_visible(1, 0) is True
    assert app_injection_visible(0, 7) is True
    assert app_injection_visible(0, 0) is False
    assert trollfools_plugin_count(["/a/A.dylib", "/a/A.dylib", "/b/B.dylib"]) == 2
    assert trollfools_plugin_count([]) == 0
    app_execs, system_execs, unresolved_execs = split_executable_targets(
        ["WeChat", "SpringBoard", "OldGame"], {"WeChat", "XHS"}, {"SpringBoard", "backboardd"})
    assert app_execs == ["WeChat"]
    assert system_execs == ["SpringBoard"]
    assert unresolved_execs == ["OldGame"]
    assert system_injection_target(system_execs, []) is True
    assert unresolved_execs == ["OldGame"] and system_injection_target([], []) is False
    assert system_injection_target([], ["com.apple.springboard"]) is True
    assert system_injection_target([], ["com.apple.Pages"]) is False
    assert system_injection_target([], ["com.example.missing"]) is False

    print("PASS: blacklist residue rule only flags explicit YES + absent Bundle ID")
    print("PASS: uninstalled Filter targets remain a separate informational set")
    print("PASS: 50k entry budget is exact and time budgets distinguish per-App timeout from global skip")
    print("PASS: RootHide configuration-permits requires supported + known + not-blacklisted state")
    print("PASS: per-App embedded evidence distinguishes unavailable / not-scanned / partial / complete-zero / evidence")
    print("PASS: mixed-source classification requires both conservative RootHide permission and active embedded diff")
    print("PASS: App injection home only shows DPKG-owned or TrollFools-injected Apps")
    print("PASS: TrollFools plugin count uses unique Load Path without calling raw evidence a plugin")
    print("PASS: Filter.Executables are split into registered-App / confirmed-system / unresolved targets")
    print("PASS: unresolved executable targets do not become system injection without system-process evidence")
    print("PASS: system Bundle classification is explicit and does not treat every com.apple.* identifier as a system process")

if __name__ == "__main__":
    main()

# Current UX rule: unresolved Filter section is exceptional and only visible when actual unresolved targets exist.
def unresolved_section_visible(unresolved_exec_count, unresolved_bundle_count):
    return unresolved_exec_count > 0 or unresolved_bundle_count > 0

assert not unresolved_section_visible(0, 0)
assert unresolved_section_visible(1, 0)
assert unresolved_section_visible(0, 1)
print('PASS: unresolved Filter section stays hidden at zero and appears only for actual unresolved targets')
