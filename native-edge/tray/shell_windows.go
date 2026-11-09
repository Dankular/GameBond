package tray

import (
	"errors"
	"math"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"
)

var (
	user32  = syscall.NewLazyDLL("user32.dll")
	shell32 = syscall.NewLazyDLL("shell32.dll")
	gdi32   = syscall.NewLazyDLL("gdi32.dll")

	procRegisterClassEx    = user32.NewProc("RegisterClassExW")
	procCreateWindowEx     = user32.NewProc("CreateWindowExW")
	procDefWindowProc      = user32.NewProc("DefWindowProcW")
	procGetMessage         = user32.NewProc("GetMessageW")
	procTranslateMessage   = user32.NewProc("TranslateMessage")
	procDispatchMessage    = user32.NewProc("DispatchMessageW")
	procPostQuitMessage    = user32.NewProc("PostQuitMessage")
	procPostMessage        = user32.NewProc("PostMessageW")
	procSetTimer           = user32.NewProc("SetTimer")
	procKillTimer          = user32.NewProc("KillTimer")
	procCreatePopupMenu    = user32.NewProc("CreatePopupMenu")
	procAppendMenu         = user32.NewProc("AppendMenuW")
	procDestroyMenu        = user32.NewProc("DestroyMenu")
	procTrackPopupMenu     = user32.NewProc("TrackPopupMenu")
	procSetForegroundWin   = user32.NewProc("SetForegroundWindow")
	procGetCursorPos       = user32.NewProc("GetCursorPos")
	procDestroyIcon        = user32.NewProc("DestroyIcon")
	procCreateIconIndirect = user32.NewProc("CreateIconIndirect")
	procDestroyWindow      = user32.NewProc("DestroyWindow")
	procShellNotifyIcon    = shell32.NewProc("Shell_NotifyIconW")
	procShellExecute       = shell32.NewProc("ShellExecuteW")
	procCreateBitmap       = gdi32.NewProc("CreateBitmap")
	procDeleteObject       = gdi32.NewProc("DeleteObject")
)

const (
	wmUser          = 0x400
	wmTray          = wmUser + 1
	wmTimer         = 0x113
	wmDestroy       = 0x2
	wmLButtonDblClk = 0x203
	wmLButtonUp     = 0x202
	wmRButtonUp     = 0x205
	wmContextMenu   = 0x7b
	wmNull          = 0
	nimAdd          = 0
	nimModify       = 1
	nimDelete       = 2
	nifMessage      = 1
	nifIcon         = 2
	nifTip          = 4
	mfString        = 0
	mfGrayed        = 1
	mfSeparator     = 0x800
	tpmReturnCmd    = 0x100
	tpmRightButton  = 2
	timerID         = 1
)

// hwndMessage is HWND_MESSAGE, (HWND)-3.
var hwndMessage = ^uintptr(2)

type point struct{ x, y int32 }
type msg struct {
	hwnd    uintptr
	message uint32
	wparam  uintptr
	lparam  uintptr
	time    uint32
	pt      point
}
type wndClassEx struct {
	size       uint32
	style      uint32
	wndProc    uintptr
	clsExtra   int32
	wndExtra   int32
	instance   uintptr
	icon       uintptr
	cursor     uintptr
	background uintptr
	menuName   *uint16
	className  *uint16
	iconSm     uintptr
}
type notifyIconData struct {
	size            uint32
	hwnd            uintptr
	id              uint32
	flags           uint32
	callbackMessage uint32
	icon            uintptr
	tip             [128]uint16
	state           uint32
	stateMask       uint32
	info            [256]uint16
	version         uint32
	infoTitle       [64]uint16
	infoFlags       uint32
	guid            [16]byte
	balloonIcon     uintptr
}
type iconInfo struct {
	icon  int32
	xHot  uint32
	yHot  uint32
	mask  uintptr
	color uintptr
}

// MenuItem is one popup entry; ID 0 with an empty label is a separator.
type MenuItem struct {
	ID      int
	Label   string
	Enabled bool
}

// Shell owns the hidden window, the notification icon and its menu. All calls
// except Quit must come from the goroutine that called Run.
type Shell struct {
	// Menu is asked for the entries each time the popup opens.
	Menu func() []MenuItem
	// OnCommand receives the chosen menu ID; OnDefault is a double click.
	OnCommand func(id int)
	OnDefault func()
	// OnTick runs once a second on the UI thread.
	OnTick func()
	// OnReady creates any visible windows on this message-loop thread.
	OnReady func()

	hwnd  uintptr
	icons map[string]uintptr
	cur   string
	tip   string
}

var current *Shell

func wndProc(hwnd, message, wparam, lparam uintptr) uintptr {
	s := current
	if s != nil {
		switch uint32(message) {
		case wmTray:
			switch uint32(lparam) {
			case wmLButtonUp, wmLButtonDblClk:
				if s.OnDefault != nil {
					s.OnDefault()
				}
			case wmRButtonUp, wmContextMenu:
				s.popup()
			}
			return 0
		case wmTimer:
			if s.OnTick != nil {
				s.OnTick()
			}
			return 0
		case wmDestroy:
			procPostQuitMessage.Call(0)
			return 0
		}
	}
	r, _, _ := procDefWindowProc.Call(hwnd, message, wparam, lparam)
	return r
}

// Run creates the icon and blocks in the message loop until Quit.
func (s *Shell) Run(color, tip string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	current = s
	cls, _ := syscall.UTF16PtrFromString("GameBondTrayWindow")
	wc := wndClassEx{className: cls, wndProc: syscall.NewCallback(wndProc)}
	wc.size = uint32(unsafe.Sizeof(wc))
	if a, _, err := procRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc))); a == 0 {
		return err
	}
	hwnd, _, err := procCreateWindowEx.Call(0, uintptr(unsafe.Pointer(cls)), uintptr(unsafe.Pointer(cls)), 0, 0, 0, 0, 0, hwndMessage, 0, 0, 0)
	if hwnd == 0 {
		return err
	}
	s.hwnd = hwnd
	s.icons = map[string]uintptr{}
	for _, c := range []string{Idle, Connected, Busy} {
		ic, err := makeIcon(c)
		if err != nil {
			return err
		}
		s.icons[c] = ic
	}
	s.cur, s.tip = color, tip
	if !s.notify(nimAdd) {
		return errors.New("Shell_NotifyIcon add failed")
	}
	procSetTimer.Call(hwnd, timerID, 1000, 0)
	if s.OnReady != nil {
		s.OnReady()
	}
	var m msg
	for {
		r, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessage.Call(uintptr(unsafe.Pointer(&m)))
	}
	procKillTimer.Call(hwnd, timerID)
	s.notify(nimDelete)
	for _, ic := range s.icons {
		procDestroyIcon.Call(ic)
	}
	procDestroyWindow.Call(hwnd)
	return nil
}

// Quit asks the loop to end; safe from any goroutine.
func (s *Shell) Quit() { procPostMessage.Call(s.hwnd, wmDestroy, 0, 0) }

func (s *Shell) notify(op uintptr) bool {
	d := notifyIconData{hwnd: s.hwnd, id: 1, flags: nifMessage | nifIcon | nifTip, callbackMessage: wmTray, icon: s.icons[s.cur]}
	d.size = uint32(unsafe.Sizeof(d))
	t := syscall.StringToUTF16(s.tip)
	if len(t) > len(d.tip) {
		t = append(t[:len(d.tip)-1], 0)
	}
	copy(d.tip[:], t)
	r, _, _ := procShellNotifyIcon.Call(op, uintptr(unsafe.Pointer(&d)))
	return r != 0
}

// Balloon shows a notification-area toast (UI thread only).
func (s *Shell) Balloon(title, body string) {
	d := notifyIconData{hwnd: s.hwnd, id: 1, flags: 16, infoFlags: 1} // NIF_INFO, NIIF_INFO
	d.size = uint32(unsafe.Sizeof(d))
	copy(d.infoTitle[:len(d.infoTitle)-1], syscall.StringToUTF16(title))
	copy(d.info[:len(d.info)-1], syscall.StringToUTF16(body))
	procShellNotifyIcon.Call(nimModify, uintptr(unsafe.Pointer(&d)))
}

// SetIcon changes the icon colour and tooltip (UI thread only).
func (s *Shell) SetIcon(color, tip string) {
	s.cur, s.tip = color, tip
	s.notify(nimModify)
}

func (s *Shell) popup() {
	if s.Menu == nil {
		return
	}
	menu, _, _ := procCreatePopupMenu.Call()
	defer procDestroyMenu.Call(menu)
	for _, it := range s.Menu() {
		if it.ID == 0 && it.Label == "" {
			procAppendMenu.Call(menu, mfSeparator, 0, 0)
			continue
		}
		flags := uintptr(mfString)
		if !it.Enabled {
			flags |= mfGrayed
		}
		l, _ := syscall.UTF16PtrFromString(it.Label)
		procAppendMenu.Call(menu, flags, uintptr(it.ID), uintptr(unsafe.Pointer(l)))
	}
	var p point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&p)))
	procSetForegroundWin.Call(s.hwnd) // required so the menu closes on an outside click
	id, _, _ := procTrackPopupMenu.Call(menu, tpmReturnCmd|tpmRightButton, uintptr(p.x), uintptr(p.y), 0, s.hwnd, 0)
	procPostMessage.Call(s.hwnd, wmNull, 0, 0)
	if id != 0 && s.OnCommand != nil {
		s.OnCommand(int(id))
	}
}

// Open starts the default handler for a URL or file.
func Open(target string) error {
	verb, _ := syscall.UTF16PtrFromString("open")
	t, err := syscall.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	r, _, _ := procShellExecute.Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(t)), 0, 0, 1)
	if r <= 32 {
		return errors.New("ShellExecute failed: " + strconv.Itoa(int(r)))
	}
	return nil
}

// Bitmap renders the 32x32 icon as top-down BGRA: a rounded square in the
// colour with the white zig-zag line the Python tray draws (its 64 px
// polyline scaled to 32).
func Bitmap(color string) []byte {
	const n = 32
	r, g, b := hexRGB(color)
	px := make([]byte, n*n*4)
	segs := [][4]float64{{6, 23.5, 13.5, 8.5}, {13.5, 8.5, 19, 18}, {19, 18, 26.5, 5.5}}
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			i := (y*n + x) * 4
			if !inRounded(float64(x)+.5, float64(y)+.5, 1, 1, 31, 31, 7) {
				continue
			}
			px[i], px[i+1], px[i+2], px[i+3] = b, g, r, 255
			for _, s := range segs {
				if distSeg(float64(x)+.5, float64(y)+.5, s) <= 1.5 {
					px[i], px[i+1], px[i+2] = 255, 255, 255
				}
			}
		}
	}
	return px
}

func makeIcon(color string) (uintptr, error) {
	px := Bitmap(color)
	mask := make([]byte, 32*4) // 1bpp, all zero: the colour bitmap decides
	hc, _, _ := procCreateBitmap.Call(32, 32, 1, 32, uintptr(unsafe.Pointer(&px[0])))
	hm, _, _ := procCreateBitmap.Call(32, 32, 1, 1, uintptr(unsafe.Pointer(&mask[0])))
	if hc == 0 || hm == 0 {
		return 0, errors.New("CreateBitmap failed")
	}
	info := iconInfo{icon: 1, mask: hm, color: hc}
	ic, _, err := procCreateIconIndirect.Call(uintptr(unsafe.Pointer(&info)))
	procDeleteObject.Call(hc)
	procDeleteObject.Call(hm)
	if ic == 0 {
		return 0, err
	}
	return ic, nil
}

func hexRGB(c string) (r, g, b byte) {
	v, _ := strconv.ParseUint(c[1:], 16, 32)
	return byte(v >> 16), byte(v >> 8), byte(v)
}

func inRounded(x, y, x0, y0, x1, y1, rad float64) bool {
	if x < x0 || x > x1 || y < y0 || y > y1 {
		return false
	}
	cx := math.Min(math.Max(x, x0+rad), x1-rad)
	cy := math.Min(math.Max(y, y0+rad), y1-rad)
	return (x-cx)*(x-cx)+(y-cy)*(y-cy) <= rad*rad
}

func distSeg(px, py float64, s [4]float64) float64 {
	dx, dy := s[2]-s[0], s[3]-s[1]
	t := ((px-s[0])*dx + (py-s[1])*dy) / (dx*dx + dy*dy)
	t = math.Min(1, math.Max(0, t))
	return math.Hypot(px-(s[0]+t*dx), py-(s[1]+t*dy))
}
