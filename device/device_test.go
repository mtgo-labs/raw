package device

import (
	"sync"
	"testing"

	"github.com/mtgo-labs/raw"
)

func TestTelegramDesktop(t *testing.T) {
	p := TelegramDesktop()
	if p.LangPack != "tdesktop" {
		t.Errorf("expected LangPack 'tdesktop', got %q", p.LangPack)
	}
}

func TestTelegramAndroid(t *testing.T) {
	p := TelegramAndroid()
	if p.LangPack != "android" {
		t.Errorf("expected LangPack 'android', got %q", p.LangPack)
	}
}

func TestTelegramIOS(t *testing.T) {
	p := TelegramIOS()
	if p.LangPack != "ios" {
		t.Errorf("expected LangPack 'ios', got %q", p.LangPack)
	}
}

func TestTelegramMacOS(t *testing.T) {
	p := TelegramMacOS()
	if p.LangPack != "macos" {
		t.Errorf("expected LangPack 'macos', got %q", p.LangPack)
	}
}

func TestTelegramWebZ(t *testing.T) {
	p := TelegramWebZ()
	if p.AppVersion != "1.28.3 Z" {
		t.Errorf("expected AppVersion '1.28.3 Z', got %q", p.AppVersion)
	}
}

func TestTelegramWebK(t *testing.T) {
	p := TelegramWebK()
	if p.LangPack != "macos" {
		t.Errorf("expected LangPack 'macos', got %q", p.LangPack)
	}
}

func TestDeviceGenerateAndroid(t *testing.T) {
	p := Android.Generate("test-session")
	if p.DeviceModel == "" {
		t.Error("expected non-empty DeviceModel")
	}
	if p.SystemVersion == "" {
		t.Error("expected non-empty SystemVersion")
	}
}

func TestDeviceGenerateIOS(t *testing.T) {
	p := IOS.Generate("test-session")
	if p.DeviceModel == "" {
		t.Error("expected non-empty DeviceModel")
	}
}

func TestDeviceGenerateWindows(t *testing.T) {
	p := Windows.Generate("test-session")
	if p.DeviceModel == "" {
		t.Error("expected non-empty DeviceModel")
	}
}

func TestDeviceGenerateLinux(t *testing.T) {
	p := Linux.Generate("test-session")
	if p.DeviceModel == "" {
		t.Error("expected non-empty DeviceModel")
	}
}

func TestDeviceGenerateMacOS(t *testing.T) {
	p := MacOS.Generate("test-session")
	if p.DeviceModel == "" {
		t.Error("expected non-empty DeviceModel")
	}
}

func TestDeviceGenerateDesktop(t *testing.T) {
	p := Desktop.Generate("test-session")
	if p.DeviceModel == "" {
		t.Error("expected non-empty DeviceModel")
	}
}

func TestDeviceGenerateWebZ(t *testing.T) {
	p := WebZ.Generate("")
	if p.AppVersion != "1.28.3 Z" {
		t.Errorf("expected AppVersion '1.28.3 Z', got %q", p.AppVersion)
	}
}

func TestDeviceGenerateUnknown(t *testing.T) {
	p := Device("unknown").Generate("test-session")
	if p.DeviceModel == "" {
		t.Error("expected fallback to generate non-empty DeviceModel")
	}
}

func TestDeviceGenerateDeterministic(t *testing.T) {
	p1 := Windows.Generate("same-id")
	p2 := Windows.Generate("same-id")
	if p1.DeviceModel != p2.DeviceModel {
		t.Errorf("expected same DeviceModel, got %q and %q", p1.DeviceModel, p2.DeviceModel)
	}
	if p1.SystemVersion != p2.SystemVersion {
		t.Errorf("expected same SystemVersion, got %q and %q", p1.SystemVersion, p2.SystemVersion)
	}
}

func TestProfileCopy(t *testing.T) {
	p := TelegramDesktop()
	cp := p.Copy()
	if cp.DeviceModel != p.DeviceModel {
		t.Error("copy should have same DeviceModel")
	}
	cp.DeviceModel = "modified"
	if p.DeviceModel == "modified" {
		t.Error("original should not be affected by copy modification")
	}
}

func TestProfileWithDevice(t *testing.T) {
	p := TelegramDesktop()
	modified := p.WithDevice("TestModel", "TestOS")
	if modified.DeviceModel != "TestModel" {
		t.Errorf("expected DeviceModel 'TestModel', got %q", modified.DeviceModel)
	}
	if modified.SystemVersion != "TestOS" {
		t.Errorf("expected SystemVersion 'TestOS', got %q", modified.SystemVersion)
	}
	if p.DeviceModel == "TestModel" {
		t.Error("original should not be modified")
	}
}

func TestProfileString(t *testing.T) {
	p := TelegramAndroid()
	s := p.String()
	if s == "" {
		t.Error("String() should not be empty")
	}
}

func TestProfileApply(t *testing.T) {
	p := TelegramAndroid()
	var cfg raw.InitConnectionConfig
	p.Apply(&cfg)

	if cfg.DeviceModel != p.DeviceModel {
		t.Errorf("expected DeviceModel %q, got %q", p.DeviceModel, cfg.DeviceModel)
	}
	if cfg.SystemVersion != p.SystemVersion {
		t.Errorf("expected SystemVersion %q, got %q", p.SystemVersion, cfg.SystemVersion)
	}
	if cfg.LanguagePack != p.LangPack {
		t.Errorf("expected LanguagePack %q, got %q", p.LangPack, cfg.LanguagePack)
	}
}

func TestProfileApplyPreservesOtherFields(t *testing.T) {
	p := TelegramIOS()
	cfg := raw.InitConnectionConfig{
		Proxy:      nil, // unset by Apply
		Parameters: nil, // unset by Apply
	}
	p.Apply(&cfg)

	if cfg.DeviceModel != p.DeviceModel {
		t.Error("Apply should set DeviceModel")
	}
	// Proxy and Parameters are not touched by Apply.
}

func TestToInitConnection(t *testing.T) {
	p := TelegramMacOS()
	ic := p.ToInitConnection()

	if ic.DeviceModel != p.DeviceModel {
		t.Errorf("expected DeviceModel %q, got %q", p.DeviceModel, ic.DeviceModel)
	}
	if ic.AppVersion != p.AppVersion {
		t.Errorf("expected AppVersion %q, got %q", p.AppVersion, ic.AppVersion)
	}
	if ic.LanguagePack != p.LangPack {
		t.Errorf("expected LanguagePack %q, got %q", p.LangPack, ic.LanguagePack)
	}
}

func TestGenerateAndroidNonEmpty(t *testing.T) {
	for i := range 100 {
		p := GenerateAndroid("session-" + string(rune('a'+i%26)))
		if p.DeviceModel == "" || p.SystemVersion == "" {
			t.Fatalf("iter %d: expected non-empty device fields", i)
		}
	}
}

func TestTelegramWebogram(t *testing.T) {
	p := TelegramWebogram()
	if p.AppVersion != "0.7.0" {
		t.Errorf("expected AppVersion '0.7.0', got %q", p.AppVersion)
	}
}

func TestDeviceGenerateWebogram(t *testing.T) {
	p := Webogram.Generate("test")
	if p.AppVersion != "0.7.0" {
		t.Errorf("expected AppVersion '0.7.0', got %q", p.AppVersion)
	}
}

func TestConcurrentGenerate(t *testing.T) {
	// All device types — exercises every lazy-init path concurrently.
	devices := []Device{Android, AndroidX, IOS, MacOS, Windows, Linux, Desktop}

	var wg sync.WaitGroup
	for range 200 {
		for _, d := range devices {
			wg.Add(1)
			go func(d Device) {
				defer wg.Done()
				p := d.Generate("concurrent-test")
				if p.DeviceModel == "" {
					t.Error("expected non-empty DeviceModel")
				}
			}(d)
		}
	}
	wg.Wait()
}

func TestInitConnectionDefaultsPreserved(t *testing.T) {
	// Verify that the raw package still applies its own defaults
	// when InitConnectionConfig fields are zero-valued.
	p := TelegramAndroid()
	ic := p.ToInitConnection()

	// Build a real config — the raw package should fill defaults for
	// fields we don't set.
	cfg := raw.Config{
		APIID:  12345,
		APIHash: "test",
	}
	cfg.InitConnection = ic

	_, err := raw.NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient with device profile: %v", err)
	}
}
