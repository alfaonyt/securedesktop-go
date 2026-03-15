//go:build windows

package main

import (
	"errors"
	"flag"
	"fmt"
	"image"
	"image/png"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	uoiName          = 2
	biRGB            = 0
	dibRGBColors     = 0
	srcCopy          = 0x00CC0020
	desktopAccessAll = 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0040 | 0x0080 | 0x0100 | 0x40000000

	smXVirtualScreen = 76
	smYVirtualScreen = 77
	smCXVirtual      = 78
	smCYVirtual      = 79
	smCXScreen       = 0
	smCYScreen       = 1

	desktopVertRes = 117
	desktopHorzRes = 118

	processPerMonitorDPIAware = 2

	dpiAwarenessContextPerMonitorAwareV2 = ^uintptr(3) // ((DPI_AWARENESS_CONTEXT)-4)

	th32csSnapProcess = 0x00000002

	processQueryInformation        = 0x0400
	processQueryLimitedInformation = 0x1000

	tokenAssignPrimary    = 0x0001
	tokenDuplicate        = 0x0002
	tokenImpersonate      = 0x0004
	tokenQuery            = 0x0008
	tokenAdjustPrivileges = 0x0020
	maximumAllowed        = 0x02000000

	securityImpersonation = 2
	tokenPrimary          = 1

	sePrivilegeEnabled = 0x00000002

	createNewConsole = 0x00000010

	logonWithProfile = 0x00000001
)

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	gdi32    = syscall.NewLazyDLL("gdi32.dll")
	shcore   = syscall.NewLazyDLL("shcore.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	procOpenInputDesktop       = user32.NewProc("OpenInputDesktop")
	procSetThreadDesktop       = user32.NewProc("SetThreadDesktop")
	procCloseDesktop           = user32.NewProc("CloseDesktop")
	procGetUserObjectInfoW     = user32.NewProc("GetUserObjectInformationW")
	procGetDC                  = user32.NewProc("GetDC")
	procReleaseDC              = user32.NewProc("ReleaseDC")
	procGetSystemMetrics       = user32.NewProc("GetSystemMetrics")
	procCreateCompatibleDC     = gdi32.NewProc("CreateCompatibleDC")
	procDeleteDC               = gdi32.NewProc("DeleteDC")
	procCreateCompatibleBitmap = gdi32.NewProc("CreateCompatibleBitmap")
	procDeleteObject           = gdi32.NewProc("DeleteObject")
	procSelectObject           = gdi32.NewProc("SelectObject")
	procBitBlt                 = gdi32.NewProc("BitBlt")
	procGetDIBits              = gdi32.NewProc("GetDIBits")
	procGetDeviceCaps          = gdi32.NewProc("GetDeviceCaps")
	procSetProcessDPIAware     = user32.NewProc("SetProcessDPIAware")
	procSetProcessDpiAwareness = shcore.NewProc("SetProcessDpiAwareness")
	procSetProcessDpiCtx       = user32.NewProc("SetProcessDpiAwarenessContext")
	procIsUserAnAdmin          = shell32.NewProc("IsUserAnAdmin")
	procCreateToolhelp32       = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW        = kernel32.NewProc("Process32FirstW")
	procProcess32NextW         = kernel32.NewProc("Process32NextW")
	procProcessIdToSessionID   = kernel32.NewProc("ProcessIdToSessionId")
	procWTSGetActiveConsoleSID = kernel32.NewProc("WTSGetActiveConsoleSessionId")
	procOpenProcess            = kernel32.NewProc("OpenProcess")
	procCloseHandle            = kernel32.NewProc("CloseHandle")
	procGetCurrentProcess      = kernel32.NewProc("GetCurrentProcess")
	procOpenProcessToken       = advapi32.NewProc("OpenProcessToken")
	procDuplicateTokenEx       = advapi32.NewProc("DuplicateTokenEx")
	procCreateProcessWithToken = advapi32.NewProc("CreateProcessWithTokenW")
	procCreateProcessAsUser    = advapi32.NewProc("CreateProcessAsUserW")
	procLookupPrivilegeValueW  = advapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPrivileges  = advapi32.NewProc("AdjustTokenPrivileges")
)

type luid struct {
	LowPart  uint32
	HighPart int32
}

type luidAndAttributes struct {
	Luid       luid
	Attributes uint32
}

type tokenPrivileges struct {
	PrivilegeCount uint32
	Privileges     [1]luidAndAttributes
}

type processEntry32 struct {
	Size            uint32
	Usage           uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	Threads         uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [260]uint16
}

type bitmapInfoHeader struct {
	BiSize          uint32
	BiWidth         int32
	BiHeight        int32
	BiPlanes        uint16
	BiBitCount      uint16
	BiCompression   uint32
	BiSizeImage     uint32
	BiXPelsPerMeter int32
	BiYPelsPerMeter int32
	BiClrUsed       uint32
	BiClrImportant  uint32
}

type rgbQuad struct {
	Blue     byte
	Green    byte
	Red      byte
	Reserved byte
}

type bitmapInfo struct {
	BmiHeader bitmapInfoHeader
	BmiColors [1]rgbQuad
}

type desktopBinder struct {
	handle syscall.Handle
	name   string
}

func (d *desktopBinder) bindInputDesktop() (name string, changed bool, secure bool, err error) {
	inputDesk, err := openInputDesktop()
	if err != nil {
		return "", false, false, fmt.Errorf("OpenInputDesktop: %w", err)
	}

	if err = setThreadDesktop(inputDesk); err != nil {
		_ = closeDesktop(inputDesk)
		return "", false, false, fmt.Errorf("SetThreadDesktop: %w", err)
	}

	if d.handle != 0 {
		_ = closeDesktop(d.handle)
	}
	d.handle = inputDesk

	name, err = desktopName(inputDesk)
	if err != nil {
		return "", false, false, fmt.Errorf("GetUserObjectInformation(UOI_NAME): %w", err)
	}

	changed = !strings.EqualFold(d.name, name)
	if changed {
		d.name = name
	}
	return name, changed, strings.EqualFold(name, "Winlogon"), nil
}

func (d *desktopBinder) close() {
	if d.handle != 0 {
		_ = closeDesktop(d.handle)
		d.handle = 0
	}
}

func main() {
	interval := flag.Duration("interval", 2*time.Second, "capture interval")
	outDir := flag.String("out", "captures", "output directory for PNG frames")
	once := flag.Bool("once", false, "capture one frame and exit")
	noAutoSystem := flag.Bool("no-auto-system", false, "disable automatic SYSTEM relaunch when elevated admin")
	systemChild := flag.Bool("system-child", false, "internal flag set for SYSTEM-launched instance")
	flag.Parse()

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		log.Fatalf("mkdir %q: %v", *outDir, err)
	}

	if !*systemChild && !*noAutoSystem && isUserAdmin() && !isSystemAccount() {
		method, err := relaunchAsSystem()
		if err != nil {
			log.Printf("automatic SYSTEM relaunch failed: %v", err)
			log.Printf("continuing in current token (secure desktop may fail with Access Denied)")
		} else {
			log.Printf("started SYSTEM instance via %s; exiting this admin instance", method)
			return
		}
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	dpiMode := enableDPIAwareness()

	binder := &desktopBinder{}
	defer binder.close()

	log.Printf("starting capture loop (out=%s interval=%s dpi=%s account=%s)", *outDir, interval.String(), dpiMode, accountLabel())
	nextTick := time.Now()
	for {
		now := time.Now()
		if now.Before(nextTick) {
			time.Sleep(nextTick.Sub(now))
		}

		currentName := binder.name
		currentName, changed, secure, err := binder.bindInputDesktop()
		if err != nil {
			log.Printf("desktop bind failed: %v", err)
			if isAccessDenied(err) {
				if !isSystemAccount() {
					log.Printf("secure desktop likely active and current token is not SYSTEM")
				}
				nextTick = nextTick.Add(*interval)
				if *once {
					break
				}
				continue
			}
		} else if changed {
			log.Printf("desktop switch detected: %s (secure=%v)", currentName, secure)
		}

		frame, err := captureFrame()
		if err != nil {
			log.Printf("capture failed: %v", err)
		} else {
			path, err := saveFrame(*outDir, currentName, frame)
			if err != nil {
				log.Printf("save failed: %v", err)
			} else {
				log.Printf("captured: %s", path)
			}
		}

		if *once {
			break
		}
		nextTick = nextTick.Add(*interval)
	}
}

func openInputDesktop() (syscall.Handle, error) {
	r1, _, e1 := procOpenInputDesktop.Call(
		0,
		1,
		uintptr(desktopAccessAll),
	)
	if r1 == 0 {
		return 0, winErr(e1)
	}
	return syscall.Handle(r1), nil
}

func setThreadDesktop(desktop syscall.Handle) error {
	r1, _, e1 := procSetThreadDesktop.Call(uintptr(desktop))
	if r1 == 0 {
		return winErr(e1)
	}
	return nil
}

func closeDesktop(desktop syscall.Handle) error {
	r1, _, e1 := procCloseDesktop.Call(uintptr(desktop))
	if r1 == 0 {
		return winErr(e1)
	}
	return nil
}

func desktopName(desktop syscall.Handle) (string, error) {
	buf := make([]uint16, 256)
	var needed uint32
	r1, _, e1 := procGetUserObjectInfoW.Call(
		uintptr(desktop),
		uintptr(uoiName),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)*2),
		uintptr(unsafe.Pointer(&needed)),
	)
	if r1 == 0 {
		return "", winErr(e1)
	}
	return syscall.UTF16ToString(buf), nil
}

func captureFrame() (*image.NRGBA, error) {
	hwnd := uintptr(0)
	screenDC, err := getDC(hwnd)
	if err != nil {
		return nil, fmt.Errorf("GetDC(NULL): %w", err)
	}
	defer releaseDC(hwnd, screenDC)

	memDC, err := createCompatibleDC(screenDC)
	if err != nil {
		return nil, fmt.Errorf("CreateCompatibleDC: %w", err)
	}
	defer deleteDC(memDC)

	x := getSystemMetric(smXVirtualScreen)
	y := getSystemMetric(smYVirtualScreen)
	w := getSystemMetric(smCXVirtual)
	h := getSystemMetric(smCYVirtual)
	if w <= 0 || h <= 0 {
		x, y = 0, 0
		w = getSystemMetric(smCXScreen)
		h = getSystemMetric(smCYScreen)
	}
	if x == 0 && y == 0 {
		// Fallback to physical desktop pixels when metrics are still DPI-virtualized.
		if dw := getDeviceCaps(screenDC, desktopHorzRes); dw > w {
			w = dw
		}
		if dh := getDeviceCaps(screenDC, desktopVertRes); dh > h {
			h = dh
		}
	}
	if w <= 0 || h <= 0 {
		return nil, errors.New("invalid screen size")
	}

	bmp, err := createCompatibleBitmap(screenDC, w, h)
	if err != nil {
		return nil, fmt.Errorf("CreateCompatibleBitmap: %w", err)
	}
	defer deleteObject(bmp)

	oldObj, err := selectObject(memDC, bmp)
	if err != nil {
		return nil, fmt.Errorf("SelectObject: %w", err)
	}
	defer func() { _, _ = selectObject(memDC, oldObj) }()

	if err = bitBlt(memDC, 0, 0, w, h, screenDC, x, y, srcCopy); err != nil {
		return nil, fmt.Errorf("BitBlt: %w", err)
	}

	var bi bitmapInfo
	bi.BmiHeader.BiSize = uint32(unsafe.Sizeof(bi.BmiHeader))
	bi.BmiHeader.BiWidth = int32(w)
	bi.BmiHeader.BiHeight = -int32(h) // top-down
	bi.BmiHeader.BiPlanes = 1
	bi.BmiHeader.BiBitCount = 32
	bi.BmiHeader.BiCompression = biRGB

	raw := make([]byte, w*h*4)
	scans, _, e1 := procGetDIBits.Call(
		uintptr(screenDC),
		uintptr(bmp),
		0,
		uintptr(h),
		uintptr(unsafe.Pointer(&raw[0])),
		uintptr(unsafe.Pointer(&bi)),
		uintptr(dibRGBColors),
	)
	if scans == 0 {
		return nil, winErr(e1)
	}

	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for i := 0; i < len(raw); i += 4 {
		img.Pix[i+0] = raw[i+2]
		img.Pix[i+1] = raw[i+1]
		img.Pix[i+2] = raw[i+0]
		img.Pix[i+3] = raw[i+3]
	}
	return img, nil
}

func saveFrame(dir, desktop string, img *image.NRGBA) (string, error) {
	safeDesktop := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return '_'
	}, desktop)
	if safeDesktop == "" {
		safeDesktop = "unknown"
	}

	name := fmt.Sprintf("frame_%s_%s.png", safeDesktop, time.Now().Format("20060102_150405.000"))
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if err = png.Encode(f, img); err != nil {
		return "", err
	}
	return path, nil
}

func getDC(hwnd uintptr) (syscall.Handle, error) {
	r1, _, e1 := procGetDC.Call(hwnd)
	if r1 == 0 {
		return 0, winErr(e1)
	}
	return syscall.Handle(r1), nil
}

func releaseDC(hwnd uintptr, dc syscall.Handle) {
	_, _, _ = procReleaseDC.Call(hwnd, uintptr(dc))
}

func getSystemMetric(idx int) int {
	r1, _, _ := procGetSystemMetrics.Call(uintptr(idx))
	return int(int32(r1))
}

func getDeviceCaps(dc syscall.Handle, idx int) int {
	r1, _, _ := procGetDeviceCaps.Call(uintptr(dc), uintptr(idx))
	return int(int32(r1))
}

func createCompatibleDC(src syscall.Handle) (syscall.Handle, error) {
	r1, _, e1 := procCreateCompatibleDC.Call(uintptr(src))
	if r1 == 0 {
		return 0, winErr(e1)
	}
	return syscall.Handle(r1), nil
}

func deleteDC(dc syscall.Handle) {
	_, _, _ = procDeleteDC.Call(uintptr(dc))
}

func createCompatibleBitmap(dc syscall.Handle, w, h int) (syscall.Handle, error) {
	r1, _, e1 := procCreateCompatibleBitmap.Call(uintptr(dc), uintptr(w), uintptr(h))
	if r1 == 0 {
		return 0, winErr(e1)
	}
	return syscall.Handle(r1), nil
}

func deleteObject(obj syscall.Handle) {
	_, _, _ = procDeleteObject.Call(uintptr(obj))
}

func selectObject(dc, obj syscall.Handle) (syscall.Handle, error) {
	r1, _, e1 := procSelectObject.Call(uintptr(dc), uintptr(obj))
	if r1 == 0 || r1 == ^uintptr(0) {
		return 0, winErr(e1)
	}
	return syscall.Handle(r1), nil
}

func bitBlt(dst syscall.Handle, x, y, cx, cy int, src syscall.Handle, sx, sy int, rop uint32) error {
	r1, _, e1 := procBitBlt.Call(
		uintptr(dst),
		uintptr(x),
		uintptr(y),
		uintptr(cx),
		uintptr(cy),
		uintptr(src),
		uintptr(sx),
		uintptr(sy),
		uintptr(rop),
	)
	if r1 == 0 {
		return winErr(e1)
	}
	return nil
}

func winErr(err error) error {
	if err == nil {
		return syscall.EINVAL
	}
	if errno, ok := err.(syscall.Errno); ok {
		if errno == 0 {
			return syscall.EINVAL
		}
		return errno
	}
	return err
}

func enableDPIAwareness() string {
	if procSetProcessDpiCtx.Find() == nil {
		if r1, _, _ := procSetProcessDpiCtx.Call(dpiAwarenessContextPerMonitorAwareV2); r1 != 0 {
			return "PerMonitorV2"
		}
	}

	if procSetProcessDpiAwareness.Find() == nil {
		hr, _, _ := procSetProcessDpiAwareness.Call(uintptr(processPerMonitorDPIAware))
		if hr == 0 {
			return "PerMonitor"
		}
		// E_ACCESSDENIED means DPI awareness was already set earlier (manifest/host).
		if uint32(hr) == 0x80070005 {
			return "AlreadySet"
		}
	}

	if procSetProcessDPIAware.Find() == nil {
		if r1, _, _ := procSetProcessDPIAware.Call(); r1 != 0 {
			return "SystemAware"
		}
	}
	return "Unaware"
}

func isUserAdmin() bool {
	if procIsUserAnAdmin.Find() != nil {
		return false
	}
	r1, _, _ := procIsUserAnAdmin.Call()
	return r1 != 0
}

func isSystemAccount() bool {
	user := strings.TrimSpace(os.Getenv("USERNAME"))
	domain := strings.TrimSpace(os.Getenv("USERDOMAIN"))
	return strings.EqualFold(user, "SYSTEM") &&
		(strings.EqualFold(domain, "NT AUTHORITY") || domain == "")
}

func accountLabel() string {
	user := strings.TrimSpace(os.Getenv("USERNAME"))
	domain := strings.TrimSpace(os.Getenv("USERDOMAIN"))
	if user == "" {
		user = "unknown"
	}
	if domain == "" {
		return user
	}
	return domain + `\` + user
}

func relaunchAsSystem() (string, error) {
	method, err := relaunchAsSystemViaWinlogon()
	if err == nil {
		return method, nil
	}
	taskName, taskErr := relaunchAsSystemViaTask()
	if taskErr == nil {
		return "task scheduler (" + taskName + ")", nil
	}
	return "", fmt.Errorf("winlogon token launch failed: %v | task scheduler fallback failed: %v", err, taskErr)
}

func relaunchAsSystemViaWinlogon() (string, error) {
	// Best effort. One or both may be unavailable for admin tokens depending on policy.
	_ = enablePrivilege("SeDebugPrivilege")
	_ = enablePrivilege("SeImpersonatePrivilege")

	sessionID, err := activeConsoleSessionID()
	if err != nil {
		return "", err
	}

	winlogonPID, err := findProcessInSession("winlogon.exe", sessionID)
	if err != nil {
		return "", err
	}

	procHandle, err := openProcessForToken(winlogonPID)
	if err != nil {
		return "", err
	}
	defer closeHandle(procHandle)

	primaryToken, err := duplicatePrimaryTokenFromProcess(procHandle)
	if err != nil {
		return "", err
	}
	defer closeHandle(primaryToken)

	_, _, cmdLine, cwd, err := buildSystemRelaunchCommand()
	if err != nil {
		return "", err
	}
	if err = createProcessWithSystemToken(primaryToken, cmdLine, cwd); err != nil {
		return "", err
	}
	return fmt.Sprintf("winlogon token (pid=%d session=%d)", winlogonPID, sessionID), nil
}

func relaunchAsSystemViaTask() (string, error) {
	_, _, runLine, _, err := buildSystemRelaunchCommand()
	if err != nil {
		return "", err
	}

	taskName := "securedesktop-go-system"
	start := time.Now().Add(2 * time.Minute).Format("15:04")

	createArgs := []string{
		"/Create",
		"/TN", taskName,
		"/SC", "ONCE",
		"/ST", start,
		"/RU", "SYSTEM",
		"/RL", "HIGHEST",
		"/TR", runLine,
		"/F",
		"/IT",
	}
	if out, err := exec.Command("schtasks.exe", createArgs...).CombinedOutput(); err != nil {
		// Some systems reject /IT with SYSTEM; retry without it.
		createArgs = createArgs[:len(createArgs)-1]
		if out2, err2 := exec.Command("schtasks.exe", createArgs...).CombinedOutput(); err2 != nil {
			return "", fmt.Errorf("schtasks /Create failed: %w: %s | retry: %w: %s", err, strings.TrimSpace(string(out)), err2, strings.TrimSpace(string(out2)))
		}
	}
	if out, err := exec.Command("schtasks.exe", "/Run", "/TN", taskName).CombinedOutput(); err != nil {
		return "", fmt.Errorf("schtasks /Run failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return taskName, nil
}

func buildSystemRelaunchCommand() (exe string, args []string, cmdLine string, cwd string, err error) {
	exe, err = os.Executable()
	if err != nil {
		return "", nil, "", "", fmt.Errorf("resolve executable: %w", err)
	}
	cwd, err = os.Getwd()
	if err != nil {
		return "", nil, "", "", fmt.Errorf("resolve cwd: %w", err)
	}

	for _, a := range os.Args[1:] {
		if strings.EqualFold(a, "-no-auto-system") || strings.EqualFold(a, "--no-auto-system") {
			continue
		}
		if strings.EqualFold(a, "-system-child") || strings.EqualFold(a, "--system-child") {
			continue
		}
		args = append(args, a)
	}
	args, err = normalizeOutArg(args)
	if err != nil {
		return "", nil, "", "", err
	}
	args = append(args, "-system-child")

	cmdLine = quoteWindowsArg(exe)
	for _, a := range args {
		cmdLine += " " + quoteWindowsArg(a)
	}
	return exe, args, cmdLine, cwd, nil
}

func activeConsoleSessionID() (uint32, error) {
	r1, _, _ := procWTSGetActiveConsoleSID.Call()
	sid := uint32(r1)
	if sid == 0xFFFFFFFF {
		return 0, errors.New("no active console session")
	}
	return sid, nil
}

func findProcessInSession(imageName string, sessionID uint32) (uint32, error) {
	snapshot, _, e1 := procCreateToolhelp32.Call(uintptr(th32csSnapProcess), 0)
	if snapshot == 0 || snapshot == ^uintptr(0) {
		return 0, fmt.Errorf("CreateToolhelp32Snapshot: %w", winErr(e1))
	}
	defer closeHandle(syscall.Handle(snapshot))

	var pe processEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	r1, _, e1 := procProcess32FirstW.Call(snapshot, uintptr(unsafe.Pointer(&pe)))
	if r1 == 0 {
		return 0, fmt.Errorf("Process32FirstW: %w", winErr(e1))
	}

	for {
		name := syscall.UTF16ToString(pe.ExeFile[:])
		if strings.EqualFold(name, imageName) {
			var sid uint32
			if ok, _, _ := procProcessIdToSessionID.Call(uintptr(pe.ProcessID), uintptr(unsafe.Pointer(&sid))); ok != 0 && sid == sessionID {
				return pe.ProcessID, nil
			}
		}
		r1, _, _ = procProcess32NextW.Call(snapshot, uintptr(unsafe.Pointer(&pe)))
		if r1 == 0 {
			break
		}
	}
	return 0, fmt.Errorf("%s not found in session %d", imageName, sessionID)
}

func openProcessForToken(pid uint32) (syscall.Handle, error) {
	r1, _, e1 := procOpenProcess.Call(uintptr(processQueryLimitedInformation), 0, uintptr(pid))
	if r1 == 0 {
		r1, _, e1 = procOpenProcess.Call(uintptr(processQueryInformation), 0, uintptr(pid))
		if r1 == 0 {
			return 0, fmt.Errorf("OpenProcess(%d): %w", pid, winErr(e1))
		}
	}
	return syscall.Handle(r1), nil
}

func duplicatePrimaryTokenFromProcess(process syscall.Handle) (syscall.Handle, error) {
	var token syscall.Handle
	access := uintptr(tokenDuplicate | tokenAssignPrimary | tokenImpersonate | tokenQuery)
	r1, _, e1 := procOpenProcessToken.Call(uintptr(process), access, uintptr(unsafe.Pointer(&token)))
	if r1 == 0 {
		return 0, fmt.Errorf("OpenProcessToken: %w", winErr(e1))
	}
	defer closeHandle(token)

	var primary syscall.Handle
	r1, _, e1 = procDuplicateTokenEx.Call(
		uintptr(token),
		uintptr(maximumAllowed),
		0,
		uintptr(securityImpersonation),
		uintptr(tokenPrimary),
		uintptr(unsafe.Pointer(&primary)),
	)
	if r1 == 0 {
		return 0, fmt.Errorf("DuplicateTokenEx: %w", winErr(e1))
	}
	return primary, nil
}

func createProcessWithSystemToken(token syscall.Handle, cmdLine, cwd string) error {
	command, err := syscall.UTF16FromString(cmdLine)
	if err != nil {
		return fmt.Errorf("UTF16 command line: %w", err)
	}
	cwdPtr, err := syscall.UTF16PtrFromString(cwd)
	if err != nil {
		return fmt.Errorf("UTF16 cwd: %w", err)
	}
	desktopPtr, _ := syscall.UTF16PtrFromString(`winsta0\default`)

	var si syscall.StartupInfo
	var pi syscall.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Desktop = desktopPtr

	r1, _, e1 := procCreateProcessWithToken.Call(
		uintptr(token),
		uintptr(logonWithProfile),
		0,
		uintptr(unsafe.Pointer(&command[0])),
		uintptr(createNewConsole),
		0,
		uintptr(unsafe.Pointer(cwdPtr)),
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if r1 == 0 {
		r2, _, e2 := procCreateProcessAsUser.Call(
			uintptr(token),
			0,
			uintptr(unsafe.Pointer(&command[0])),
			0,
			0,
			0,
			uintptr(createNewConsole),
			0,
			uintptr(unsafe.Pointer(cwdPtr)),
			uintptr(unsafe.Pointer(&si)),
			uintptr(unsafe.Pointer(&pi)),
		)
		if r2 == 0 {
			return fmt.Errorf("CreateProcessWithTokenW: %w | CreateProcessAsUserW: %w", winErr(e1), winErr(e2))
		}
	}
	closeHandle(syscall.Handle(pi.Thread))
	closeHandle(syscall.Handle(pi.Process))
	return nil
}

func enablePrivilege(name string) error {
	current, _, _ := procGetCurrentProcess.Call()
	var token syscall.Handle
	r1, _, e1 := procOpenProcessToken.Call(current, uintptr(tokenAdjustPrivileges|tokenQuery), uintptr(unsafe.Pointer(&token)))
	if r1 == 0 {
		return winErr(e1)
	}
	defer closeHandle(token)

	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	var id luid
	r1, _, e1 = procLookupPrivilegeValueW.Call(0, uintptr(unsafe.Pointer(namePtr)), uintptr(unsafe.Pointer(&id)))
	if r1 == 0 {
		return winErr(e1)
	}

	var tp tokenPrivileges
	tp.PrivilegeCount = 1
	tp.Privileges[0].Luid = id
	tp.Privileges[0].Attributes = sePrivilegeEnabled
	r1, _, e1 = procAdjustTokenPrivileges.Call(
		uintptr(token),
		0,
		uintptr(unsafe.Pointer(&tp)),
		0,
		0,
		0,
	)
	if r1 == 0 {
		return winErr(e1)
	}
	return nil
}

func closeHandle(h syscall.Handle) {
	if h == 0 || uintptr(h) == ^uintptr(0) {
		return
	}
	_, _, _ = procCloseHandle.Call(uintptr(h))
}

func quoteWindowsArg(s string) string {
	if s == "" {
		return `""`
	}
	needsQuotes := false
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '"' {
			needsQuotes = true
			break
		}
	}
	if !needsQuotes {
		return s
	}
	escaped := strings.ReplaceAll(s, `"`, `\"`)
	return `"` + escaped + `"`
}

func isAccessDenied(err error) bool {
	var errno syscall.Errno
	return errors.As(err, &errno) && errno == syscall.ERROR_ACCESS_DENIED
}

func normalizeOutArg(args []string) ([]string, error) {
	ret := append([]string{}, args...)
	seenOut := false

	for i := 0; i < len(ret); i++ {
		a := ret[i]
		if strings.HasPrefix(a, "-out=") || strings.HasPrefix(a, "--out=") {
			seenOut = true
			parts := strings.SplitN(a, "=", 2)
			abs, err := toAbsPath(parts[1])
			if err != nil {
				return nil, err
			}
			ret[i] = parts[0] + "=" + abs
			continue
		}
		if a == "-out" || a == "--out" {
			seenOut = true
			if i+1 >= len(ret) {
				return nil, errors.New("missing value for -out")
			}
			abs, err := toAbsPath(ret[i+1])
			if err != nil {
				return nil, err
			}
			ret[i+1] = abs
		}
	}

	if !seenOut {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("resolve cwd for out path: %w", err)
		}
		ret = append(ret, "-out", filepath.Join(cwd, "captures"))
	}
	return ret, nil
}

func toAbsPath(p string) (string, error) {
	if filepath.IsAbs(p) {
		return p, nil
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("resolve absolute path for %q: %w", p, err)
	}
	return abs, nil
}
