# securedesktop-go (Proof of Concept)

Windows proof of concept that captures secure-desktop with a simple Go program :

- Detect active desktop changes (`OpenInputDesktop` + `SetThreadDesktop` + `GetUserObjectInformation(UOI_NAME)`).
- Capture the current desktop frame with GDI (`GetDC` + `BitBlt` + `GetDIBits`).
- Mark secure desktop state when desktop name is `Winlogon`.
- Attempt automatic SYSTEM relaunch when started elevated (admin), using:
  1. Winlogon token duplication (primary path),
  2. Task Scheduler fallback.

## Why This Exists

This PoC was built to understand and reproduce how secure desktop capture can be handled using a simple program.

## Requirements

- Windows
- Go 1.26+
- For secure desktop access: elevated launch (Administrator).  
  SYSTEM-level capture may still depend on local policy/security settings.

## Build

```powershell
go build .
```

## Run

```powershell
.\securedesktop-go.exe
```

Useful flags:

- `-interval 2s` capture interval (default: `2s`)
- `-out captures` output directory for PNG frames
- `-once` capture one frame then exit
- `-no-auto-system` disable automatic SYSTEM relaunch logic

Example:

```powershell
.\securedesktop-go.exe -interval 2s -out captures
```

## Notes

- The process enables DPI awareness to avoid partial top-left captures on scaled displays (for example, 200% scaling).
- When secure desktop is active and token access is insufficient, the tool logs access-denied and skips that capture cycle.

## Security/Ethics

This is a research PoC. Only run on systems you own or are explicitly authorized to test.
