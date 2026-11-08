# Crash report to pseudocode

Open the binaries from the crashed build in a workspace, then drop an Apple `.ips` report on the workspace or choose **File → Open Crash Report…**. MacScope reads both Apple's metadata-plus-JSON envelope and a standalone JSON report. The report opens read only in a separate window.

The report selects the crashed thread and displays its recorded registers. ARM64 `x0`–`x28`, frame/link/stack/program counters and status/fault registers, and Intel general-purpose, instruction, stack and status registers are supported. Values retain their full unsigned precision. They are the selected thread's state at termination; older stack frames have no separate register snapshots.

Each frame is matched against the loaded images using the build UUID. The reported image offset and load base identify the runtime crash address; the matching binary's preferred image base translates that offset into the workspace address. Names and report paths never authorize a match. Duplicate UUID candidates, out-of-range addresses and stale binary owners refuse navigation.

When the crashed thread's first frame matches an analyzed instruction inside exactly one function, MacScope selects that image and opens pseudocode automatically. Clicking another resolved frame performs the same navigation. The existing decompiler selection remains in effect. Exact verified source mappings reveal the corresponding pseudocode text; absent, degraded or ambiguous mappings show the function and explain that no unique line can be selected.

Missing binaries remain visible with their UUID. Load the matching build using the existing binary-loading commands, then reopen the report to capture the new image set. Reports do not search the filesystem, load paths named by untrusted input, or reconstruct registers for older frames. Report data is session-local and is not saved into the workspace package.
