# VibeBoot

Everything that starts with this PC, from every hiding place, with who signed each and an undo
for every change.

Task Manager's Startup tab misses scheduled tasks and services; the expert tools show everything
and drown you in it. VibeBoot sits in between: one list of what starts with Windows, from the Run
keys, the startup folders, logon and boot tasks, automatic services and drivers. Each entry shows
who signed its file, whether the file is still there and, when Windows can tell, when it was
added. Microsoft's own entries are folded away so the rest stands out.

Switch an entry off and it is done the way Task Manager does it, so Windows agrees. Every change
goes into a journal with an Undo, also from a later session. It is written in Rust with a native
Slint interface, with no browser engine inside.

## What it does and doesn't do

- **Switches, never deletes.** Run entries and startup files are switched the Task Manager way; a
  task is switched off with its Enabled flag; an automatic service is set to Manual (not
  Disabled, so something that needs it can still start it). Drivers and entries set by a policy
  are shown, not switched.
- **Microsoft-signed services stay as they are.** Their switch is refused, so you can't cut a
  piece of Windows off by accident.
- **Admin only when needed.** The app never runs as administrator. A full scan (the tasks hidden
  from your account) or a change to something PC-wide asks Windows once, and a short helper does
  just that one job.
- **Reports.** Copy or save the list as plain text, every entry with its location, command,
  signer, dates and state.
- **Portable.** On a USB stick (or with a file named `portable` beside the exe) it keeps its
  settings and journal in a `VibeBoot-data` folder next to the exe, one journal per PC, so Undo
  still works on the next visit.

## What it touches on your PC

- Your settings in `%APPDATA%\com.tedkj.vibeboot` and the journal in
  `%LOCALAPPDATA%\com.tedkj.vibeboot` (or `VibeBoot-data` beside the exe when portable).
- The startup entries you switch, and nothing else.
- When the helper switches a task off, it keeps a record in `HKLM\SOFTWARE\VibeBoot` so a later
  Undo can be trusted. Uninstalling leaves that key; an administrator can remove it with
  `reg delete "HKLM\SOFTWARE\VibeBoot" /f`.
- A service it switched to Manual gets a note in its own registry key (`VibeBootSwitchedOff`),
  cleared again when it is switched back on.

## What it connects to

Nothing, unless you press "Check this install" in About. That fetches the signed release list
from getvibeware.com and compares this copy's files with it.

## Download

Get the installer from [Releases](https://github.com/tedkj/vibeboot/releases) or from
[getvibeware.com](https://getvibeware.com). It installs for your user only, without admin rights.
The installer, VibeBoot.exe and its uninstaller are code signed by "Open Source Developer Ted
Kenneth Johansen" (the certificate's name; see the file's Properties › Digital Signatures).
Compare the installer's SHA-256 with the one in `SHA256SUMS.txt` on the release page:

```powershell
Get-FileHash .\VibeBoot_0.1.0-preview_x64-setup.exe
```

## Building from source

You need a current stable Rust toolchain on Windows (the MSVC target).

```sh
cargo build --release --locked
```

The app is then at `target\release\vibeboot.exe`.

### Building the installer

`installer\build.ps1` builds the app and its installer,
`target\release\bundle\VibeBoot_<version>_x64-setup.exe`. It needs the official NSIS 3.13:
download `nsis-3.13.zip` from SourceForge (SHA-256
`ba63dffc4410ee89193e1cb5a41989991bd77c61068da17e3156d136b7b0b3d8`) and unpack it to
`_tools\nsis-3.13` in the folder that holds this repository (`..\_tools\nsis-3.13`). The script
checks that whole folder against a pinned hash before it runs anything from it.
`installer\notices.ps1` writes `THIRD-PARTY-NOTICES.txt` for each build (every crate the app
links, with its licence text), and the installer puts it and `LICENSE` next to the app.

`vendor/` holds Slint's `i-slint-core` 1.18.1 with one small repaint fix; `vendor/README.md` says
what changed and why.

## License

[AGPL-3.0](LICENSE). Use it, change it, share it. If you hand out a changed version, or run one as
a service for other people, you share your changes under the same license. Slint is used under
its GPLv3 option.

Made in Norway by Ted K. Johansen.
