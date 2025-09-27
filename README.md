# BackupWorkstation
Portable, field-friendly workstation backup and restore tool built for predictable, surgical restores. Captures the user-scoped settings technicians actually care about while avoiding risky hive replacements and brittle, app-specific edge cases.

## Features
- Exports targeted HKCU subkeys (not the whole hive) for safe, reliable backups
- Per-key .reg export files with clear, per-item logging
- DPAPI-safe execution when run asInvoker so user secrets decrypt correctly
- Manifest-driven target list for easy add/remove of keys without code changes
- Lightweight dark-themed UI with live log, progress, and watermarked branding
- Fallback detection that skips missing or empty registry keys
- Extensible: add app-specific exports (files, folders, or registry keys) cleanly

## Installation
- Download the portable release zip for your build.
- Extract to a technician tools folder or USB drive.
- Run the EXE as the standard logged-in user (do not run elevated unless system-level access is required).
- If running from a network share, ensure execution and code-signing policies allow the binary to run.

## Quick Start
- Launch BackupWorkstation.exe as the user you want to back up.
- Set a backup destination using the Browse control.
- (Optional) Enter a source username for labeling — exports are taken from the current user context.
- Click Start Backup and watch the live log for per-key results.
- Verify the backup folder contains .reg files and a manifest describing exported keys.

## Usage Details
### Export behavior
- Each configured target is exported to its own .reg file named after the target (optionally timestamped).
- Keys that do not exist or are empty are skipped with a warning in the log.
- Exports use reg.exe export so exports are standard Windows .reg files that can be re-imported.
### Restore guidance
- Import individual .reg files using the restore tool or reg.exe import as appropriate.
- Do not attempt to replace the entire HKCU hive from a live session; the hive is locked while the user is logged in.
- For settings that require elevation (HKLM or system drivers), use a small elevated helper process and keep DPAPI-dependent restores in the non-elevated user context.
### DPAPI notes
- Keep backup and restore operations running in the same user context that owns DPAPI secrets.
- If the app is forced to run elevated (requireAdministrator) DPAPI-protected secrets (like Chrome/Edge AES keys) may not decrypt.

## Configuration
### Targets manifest
The tool supports a JSON manifest that maps friendly names to registry paths. Example:
{
  "Console": "HKCU\\Console",
  "Taskbar": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Taskband",
  "Environment": "HKCU\\Environment",
  "Chrome": "HKCU\\Software\\Google\\Chrome"
}

## Options
- Timestamped filenames — enable to keep versioned exports.
- Parallel export mode — speeds large exports (use with care; increases CPU and IO).
- Add custom app-targets or file-based exports via the manifest.

## Troubleshooting
- "Failed to start reg.exe"  -->  Ensure %SystemRoot%\\System32 is in PATH and reg.exe is accessible.
- [UNABLE TO DECRYPT] for Chrome/Edge secrets  -->  Run the app without elevation so DPAPI keys match the logged-in user.
- Registry export skipped  -->  Check the live log for key-not-found warnings; the tool intentionally skips missing or empty keys.
- Permissions or locked hive errors  -->  You cannot replace HKCU while the user is logged in. Use targeted imports or unload the hive from another account if absolutely necessary (risky).
  Logs and a timestamped diagnostics file are written to the backup folder; include these when reporting issues.

## Contributing
- Fork the repo, implement small, well-documented changes, and open a PR.
- Add new registry targets to the manifest rather than hardcoding them.
- Keep UI changes simple and field-focused; prefer transparency over automation that hides risk.
- Include unit-tests for parsing/config behavior and manual test notes for UI flows.

CLI / Automation examples
Export a single key using the shipped logic (example wrapper):
# Example: export HKCU\Console to C:\Backups\Console.reg
reg.exe export "HKCU\Console" "C:\Backups\Console.reg" /y


Headless usage idea: call the exe with a manifest path and output folder from task scheduler or a technician script for automated capture.

License
Include your chosen license file (recommended: MIT). If no license is present, the project is assumed MIT for convenience until you pick a specific license.