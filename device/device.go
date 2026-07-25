// Package device generates realistic Telegram client device profiles for
// mtgo-raw's initConnection.
//
// A [Profile] bundles the device identity fields (DeviceModel, SystemVersion,
// LangPack, …) that Telegram sees during initConnection. It can be injected
// directly into a [raw.InitConnectionConfig] via [Profile.Apply].
//
// Profiles can be:
//   - Picked from official presets: [TelegramDesktop], [TelegramAndroid], …
//   - Generated deterministically from a uniqueID: [GenerateAndroid], …
//   - Generated via the [Device] enum: [Android].Generate("session-1")
//
// Deterministic generation means the same uniqueID always yields the same
// device model and system version — useful for stable session identities
// across restarts.
package device

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"runtime"
	"sync"

	"github.com/mtgo-labs/raw"
)

// Device represents a Telegram client device type.
type Device string

const (
	// Android is the official Telegram Android client.
	Android Device = "android"
	// AndroidX is the Telegram-X Android client.
	AndroidX Device = "android_x"
	// IOS is the official Telegram iOS client.
	IOS Device = "ios"
	// MacOS is the official Telegram macOS client.
	MacOS Device = "macos"
	// Windows is Telegram Desktop with a Windows system version.
	Windows Device = "windows"
	// Linux is Telegram Desktop with a Linux system version.
	Linux Device = "linux"
	// Desktop is Telegram Desktop with a randomly chosen OS.
	Desktop Device = "desktop"
	// WebZ is the Telegram Web Z (React) client.
	WebZ Device = "web_z"
	// WebK is the Telegram Web K client.
	WebK Device = "web_k"
	// Webogram is the Telegram Webogram client.
	Webogram Device = "webogram"
)

// Generate returns a [Profile] with device info for the given device type.
//
// uniqueID controls deterministic randomness — the same value always
// produces the same DeviceModel and SystemVersion. When empty, the values
// are chosen at random.
func (d Device) Generate(uniqueID string) Profile {
	switch d {
	case Android:
		return GenerateAndroid(uniqueID)
	case AndroidX:
		return GenerateAndroidX(uniqueID)
	case IOS:
		return GenerateIOS(uniqueID)
	case MacOS:
		return GenerateMacOS(uniqueID)
	case Windows:
		return generateDesktop("windows", uniqueID)
	case Linux:
		return generateDesktop("linux", uniqueID)
	case Desktop:
		return generateDesktop("", uniqueID)
	case WebZ:
		return TelegramWebZ()
	case WebK:
		return TelegramWebK()
	case Webogram:
		return TelegramWebogram()
	default:
		return generateDesktop("", uniqueID)
	}
}

// Profile represents a Telegram client device identity: the device fields
// reported to Telegram during initConnection.
type Profile struct {
	// DeviceModel is the hardware model (e.g. "iPhone 13 Pro Max").
	DeviceModel string
	// SystemVersion is the OS version (e.g. "SDK 31", "Windows 10").
	SystemVersion string
	// AppVersion is the client app version (e.g. "8.4.1 (2522)").
	AppVersion string
	// LangCode is the two-letter ISO 639-1 UI language code (e.g. "en").
	LangCode string
	// SystemLangCode is the device-level language code (e.g. "en-US").
	SystemLangCode string
	// LangPack names the translation pack (e.g. "tdesktop", "android").
	LangPack string
}

// String returns a formatted multi-line representation of the Profile.
func (p Profile) String() string {
	return fmt.Sprintf("Profile{\n"+
		"    DeviceModel:    %s\n"+
		"    SystemVersion:  %s\n"+
		"    AppVersion:     %s\n"+
		"    LangCode:       %s\n"+
		"    SystemLangCode: %s\n"+
		"    LangPack:       %s\n"+
		"}",
		p.DeviceModel, p.SystemVersion,
		p.AppVersion, p.LangCode, p.SystemLangCode, p.LangPack)
}

// Copy returns a shallow copy of the Profile.
func (p Profile) Copy() Profile { return p }

// WithDevice overrides DeviceModel and SystemVersion and returns a new Profile.
func (p Profile) WithDevice(deviceModel, systemVersion string) Profile {
	cp := p.Copy()
	cp.DeviceModel = deviceModel
	cp.SystemVersion = systemVersion
	return cp
}

// ToInitConnection converts the Profile into a [raw.InitConnectionConfig].
//
// Use this when building a [raw.Config] by hand:
//
//	cfg.InitConnection = profile.ToInitConnection()
func (p Profile) ToInitConnection() raw.InitConnectionConfig {
	return raw.InitConnectionConfig{
		DeviceModel:        p.DeviceModel,
		SystemVersion:      p.SystemVersion,
		AppVersion:         p.AppVersion,
		LanguageCode:       p.LangCode,
		SystemLanguageCode: p.SystemLangCode,
		LanguagePack:       p.LangPack,
	}
}

// Apply injects the Profile's device identity into a [raw.InitConnectionConfig].
// Only device fields are modified; Proxy and Parameters are left unchanged.
//
// Example:
//
//	cfg := raw.Config{APIID: 12345}
//	device.Android.Generate("my-session").Apply(&cfg.InitConnection)
//	client, err := raw.NewClient(cfg)
func (p Profile) Apply(cfg *raw.InitConnectionConfig) {
	cfg.DeviceModel = p.DeviceModel
	cfg.SystemVersion = p.SystemVersion
	cfg.AppVersion = p.AppVersion
	cfg.LanguageCode = p.LangCode
	cfg.SystemLanguageCode = p.SystemLangCode
	cfg.LanguagePack = p.LangPack
}

// --- Presets ---

// TelegramDesktop returns a static profile mimicking Telegram Desktop on Windows.
func TelegramDesktop() Profile {
	return Profile{
		DeviceModel:    "Desktop",
		SystemVersion:  "Windows 10",
		AppVersion:     "5.10.0 x64",
		LangCode:       "en",
		SystemLangCode: "en-US",
		LangPack:       "tdesktop",
	}
}

// TelegramAndroid returns a static profile mimicking the official Telegram Android app.
func TelegramAndroid() Profile {
	return Profile{
		DeviceModel:    "Samsung SM-G998B",
		SystemVersion:  "SDK 31",
		AppVersion:     "8.4.1 (2522)",
		LangCode:       "en",
		SystemLangCode: "en-US",
		LangPack:       "android",
	}
}

// TelegramAndroidX returns a static profile mimicking Telegram-X for Android.
func TelegramAndroidX() Profile {
	return Profile{
		DeviceModel:    "Samsung SM-G998B",
		SystemVersion:  "SDK 31",
		AppVersion:     "8.4.1 (2522)",
		LangCode:       "en",
		SystemLangCode: "en-US",
		LangPack:       "android",
	}
}

// TelegramIOS returns a static profile mimicking the official Telegram iOS app.
func TelegramIOS() Profile {
	return Profile{
		DeviceModel:    "iPhone 13 Pro Max",
		SystemVersion:  "14.8.1",
		AppVersion:     "8.4",
		LangCode:       "en",
		SystemLangCode: "en-US",
		LangPack:       "ios",
	}
}

// TelegramMacOS returns a static profile mimicking the official Telegram macOS app.
func TelegramMacOS() Profile {
	return Profile{
		DeviceModel:    "MacBook Pro",
		SystemVersion:  "macOS 12.0.1",
		AppVersion:     "8.4",
		LangCode:       "en",
		SystemLangCode: "en-US",
		LangPack:       "macos",
	}
}

// TelegramWebZ returns a static profile mimicking Telegram Web Z (React client).
func TelegramWebZ() Profile {
	return Profile{
		DeviceModel:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
		SystemVersion:  "Windows",
		AppVersion:     "1.28.3 Z",
		LangCode:       "en",
		SystemLangCode: "en-US",
		LangPack:       "",
	}
}

// TelegramWebK returns a static profile mimicking Telegram Web K client.
func TelegramWebK() Profile {
	return Profile{
		DeviceModel:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
		SystemVersion:  "Win32",
		AppVersion:     "1.0.1 K",
		LangCode:       "en",
		SystemLangCode: "en-US",
		LangPack:       "macos",
	}
}

// TelegramWebogram returns a static profile mimicking Telegram Webogram client.
func TelegramWebogram() Profile {
	return Profile{
		DeviceModel:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
		SystemVersion:  "Win32",
		AppVersion:     "0.7.0",
		LangCode:       "en",
		SystemLangCode: "en-US",
		LangPack:       "",
	}
}

// --- Generate functions ---

// GenerateDesktop generates a randomized Telegram Desktop profile.
//
// system must be "windows", "macos", or "linux". When empty, it is chosen
// deterministically from uniqueID (or randomly if uniqueID is also empty).
func GenerateDesktop(system string, uniqueID string) Profile {
	return generateDesktop(system, uniqueID)
}

func generateDesktop(system string, uniqueID string) Profile {
	base := TelegramDesktop()

	if system == "" {
		system = hashToValue(hashStr(uniqueID), []string{"windows", "macos", "linux"})
	}

	var info deviceInfo
	switch system {
	case "windows":
		info = randomWindowsDevice(uniqueID)
	case "macos":
		info = randomMacOSDevice(uniqueID)
	default:
		info = randomLinuxDevice(uniqueID)
	}

	return base.WithDevice(info.model, info.version)
}

// GenerateAndroid generates a randomized Telegram Android profile.
func GenerateAndroid(uniqueID string) Profile {
	base := TelegramAndroid()
	info := randomAndroidDevice(uniqueID)
	return base.WithDevice(info.model, info.version)
}

// GenerateAndroidX generates a randomized Telegram-X Android profile.
func GenerateAndroidX(uniqueID string) Profile {
	base := TelegramAndroidX()
	info := randomAndroidDevice(uniqueID)
	return base.WithDevice(info.model, info.version)
}

// GenerateIOS generates a randomized Telegram iOS profile.
func GenerateIOS(uniqueID string) Profile {
	base := TelegramIOS()
	info := randomIOSDevice(uniqueID)
	return base.WithDevice(info.model, info.version)
}

// GenerateMacOS generates a randomized Telegram macOS profile.
func GenerateMacOS(uniqueID string) Profile {
	base := TelegramMacOS()
	info := randomMacOSDevice(uniqueID)
	return base.WithDevice(info.model, info.version)
}

// GenerateDesktopWithArch generates a Telegram Desktop profile using the
// actual system architecture for DeviceModel. The system version is chosen
// the same way as [GenerateDesktop].
func GenerateDesktopWithArch(system string, uniqueID string) Profile {
	p := generateDesktop(system, uniqueID)

	arch := runtime.GOARCH
	var deviceModel string
	switch arch {
	case "amd64":
		deviceModel = "PC 64bit"
	case "386":
		deviceModel = "PC 32bit"
	default:
		deviceModel = arch
	}

	return p.WithDevice(deviceModel, p.SystemVersion)
}

// --- internal helpers ---

// deviceInfo pairs a device model with its system version.
type deviceInfo struct {
	model   string
	version string
}

// iosOnce guards lazy initialization of the iOS device list (the only list
// that still pre-materializes due to per-model version constraints).
var iosOnce sync.Once

// hashStr returns a deterministic uint64 hash of uniqueID.
// When uniqueID is empty, 32 random bytes are used instead.
func hashStr(uniqueID string) uint64 {
	var b []byte
	if uniqueID == "" {
		b = make([]byte, 32)
		_, _ = rand.Read(b)
	} else {
		b = []byte(uniqueID)
	}
	h := sha1.Sum(b)
	return binary.BigEndian.Uint64(h[:8]) % 1_000_000_000_000
}

// hashToValue deterministically picks an element from values using hashID.
func hashToValue[T any](hashID uint64, values []T) T {
	return values[hashID%uint64(len(values))]
}

// cleanAndSimplify collapses consecutive spaces and trims leading/trailing space.
func cleanAndSimplify(text string) string {
	result := make([]byte, 0, len(text))
	prevSpace := true
	for i := 0; i < len(text); i++ {
		if text[i] == ' ' {
			if !prevSpace {
				result = append(result, ' ')
				prevSpace = true
			}
			continue
		}
		result = append(result, text[i])
		prevSpace = false
	}
	return string(result)
}
