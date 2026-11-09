package tray

import (
	"errors"
	"runtime"
	"sync"
	"syscall"

	webview "github.com/jchv/go-webview2"
)

// Widget hosts the desktop interface in its own native window, without opening
// a browser tab. Its renderer runs on a dedicated COM/message-loop thread.
type Widget struct {
	URL, ProfilePath string
	once             sync.Once
	ready            chan struct{}
	browser          webview.WebView
	err              error
	hwnd, oldProc    uintptr
	closing          bool // renderer thread only
}

var widgetWindows sync.Map
var widgetWindowCallback = syscall.NewCallback(widgetWindowProc)
var widgetSetWindowLong = user32.NewProc("SetWindowLongPtrW")
var widgetCallWindowProc = user32.NewProc("CallWindowProcW")
var widgetShowWindow = user32.NewProc("ShowWindow")

func widgetWindowProc(hwnd, message, wparam, lparam uintptr) uintptr {
	if value, ok := widgetWindows.Load(hwnd); ok {
		w := value.(*Widget)
		if message == 0x10 && !w.closing { // WM_CLOSE hides to tray
			widgetShowWindow.Call(hwnd, 0)
			return 0
		}
		r, _, _ := widgetCallWindowProc.Call(w.oldProc, hwnd, message, wparam, lparam)
		return r
	}
	r, _, _ := procDefWindowProc.Call(hwnd, message, wparam, lparam)
	return r
}

func (w *Widget) start() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	w.browser = webview.NewWithOptions(webview.WebViewOptions{DataPath: w.ProfilePath, AutoFocus: true, WindowOptions: webview.WindowOptions{Title: "GameBond", Width: 1120, Height: 760, Center: true}})
	if w.browser == nil {
		w.err = errors.New("could not create the desktop window; WebView2 runtime is required")
		close(w.ready)
		return
	}
	w.hwnd = uintptr(w.browser.Window())
	w.browser.SetSize(860, 560, webview.HintMin)
	widgetWindows.Store(w.hwnd, w)
	w.oldProc, _, _ = widgetSetWindowLong.Call(w.hwnd, ^uintptr(3), widgetWindowCallback) // GWLP_WNDPROC=-4
	style, _, _ := user32.NewProc("GetWindowLongPtrW").Call(w.hwnd, ^uintptr(15))
	widgetSetWindowLong.Call(w.hwnd, ^uintptr(15), style&^0x00c00000) // retain resize borders; custom title bar
	user32.NewProc("SetWindowPos").Call(w.hwnd, 0, 0, 0, 0, 0, 0x27)
	w.browser.Bind("gamebondWindow", func(action string) error {
		switch action {
		case "hide":
			widgetShowWindow.Call(w.hwnd, 0)
		case "minimize":
			widgetShowWindow.Call(w.hwnd, 6)
		case "maximize":
			maximized, _, _ := user32.NewProc("IsZoomed").Call(w.hwnd)
			if maximized != 0 {
				widgetShowWindow.Call(w.hwnd, 9)
			} else {
				widgetShowWindow.Call(w.hwnd, 3)
			}
		case "drag":
			user32.NewProc("ReleaseCapture").Call()
			procPostMessage.Call(w.hwnd, 0xa1, 2, 0) // WM_NCLBUTTONDOWN, HTCAPTION
		case "reload":
			w.browser.Dispatch(func() { w.browser.Navigate(w.URL) })
		default:
			return errors.New("unknown window action")
		}
		return nil
	})
	w.browser.Navigate(w.URL)
	close(w.ready)
	w.browser.Run()
	widgetWindows.Delete(w.hwnd)
}

func (w *Widget) Show() error {
	w.once.Do(func() { w.ready = make(chan struct{}); go w.start() })
	<-w.ready
	if w.err != nil {
		return w.err
	}
	w.browser.Dispatch(func() { widgetShowWindow.Call(w.hwnd, 9); procSetForegroundWin.Call(w.hwnd) })
	return nil
}

func (w *Widget) Close() {
	if w.ready == nil {
		return
	}
	<-w.ready
	if w.browser != nil {
		w.browser.Dispatch(func() { w.closing = true; w.browser.Destroy() })
	}
}
