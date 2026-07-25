package device

// Auto-generated macOS device models and system versions

var macOSRawDeviceModels = []string{
	"MacBookPro16,4",
	"MacBookPro16,3",
	"MacBookPro16,2",
	"MacBookPro16,1",
	"MacBookPro15,4",
	"MacBookPro15,3",
	"MacBookPro15,2",
	"MacBookPro15,1",
	"MacBookPro14,3",
	"MacBookPro14,2",
	"MacBookPro14,1",
	"MacBookPro13,3",
	"MacBookPro13,2",
	"MacBookPro13,1",
	"MacBookPro12,1",
	"MacBookPro11,5",
	"MacBookPro11,4",
	"MacBookPro11,3",
	"MacBookPro11,2",
	"MacBookPro11,1",
	"MacBookPro10,2",
	"MacBookPro10,1",
	"MacBookAir9,1",
	"MacBookAir8,2",
	"MacBookAir8,1",
	"MacBookAir7,2",
	"MacBookAir7,2",
	"MacBookAir7,1",
	"MacBookAir6,2",
	"MacBookAir6,1",
	"MacBookAir6,2",
	"MacBook10,1",
	"MacBook9,1",
	"MacBook8,2",
	"MacBook8,1",
	"MacPro7,1",
	"MacPro6,1",
	"iMac20,2",
	"iMac20,1",
	"iMac19,1",
	"iMac18,3",
	"iMac18,2",
	"iMac18,1",
	"iMac17,1",
	"iMac17,1",
	"iMac17,1",
	"iMac16,2",
	"iMac16,1",
	"iMac15,2",
	"iMac15,1",
	"iMac14,4",
	"iMac14,3",
	"iMac14,2",
	"iMac14,1",
	"iMacPro1,1",
}

var macOSSystemVersions = []string{
	"macOS 10.12",
	"macOS 10.12.1",
	"macOS 10.12.2",
	"macOS 10.12.3",
	"macOS 10.12.4",
	"macOS 10.12.5",
	"macOS 10.12.6",
	"macOS 10.13",
	"macOS 10.13.1",
	"macOS 10.13.2",
	"macOS 10.13.3",
	"macOS 10.13.4",
	"macOS 10.13.5",
	"macOS 10.13.6",
	"macOS 10.14",
	"macOS 10.14.1",
	"macOS 10.14.2",
	"macOS 10.14.3",
	"macOS 10.14.4",
	"macOS 10.14.5",
	"macOS 10.14.6",
	"macOS 10.15",
	"macOS 10.15.1",
	"macOS 10.15.2",
	"macOS 10.15.3",
	"macOS 10.15.4",
	"macOS 10.15.5",
	"macOS 10.15.6",
	"macOS 10.15.7",
	"macOS 11.0",
	"macOS 11.0.1",
	"macOS 11.1",
	"macOS 11.2",
	"macOS 11.2.1",
	"macOS 11.2.2",
	"macOS 11.2.3",
	"macOS 11.3",
	"macOS 11.3.1",
	"macOS 11.4",
	"macOS 11.5",
	"macOS 11.5.1",
	"macOS 11.5.2",
	"macOS 11.6",
	"macOS 11.6.1",
	"macOS 11.6.2",
	"macOS 12.0",
	"macOS 12.0.1",
	"macOS 12.1",
}

// macOSFromIdentifier converts a macOS model identifier (e.g. MacBookPro16,4) to a human-readable name.
func macOSFromIdentifier(model string) string {
	var words []string
	word := ""
	for _, ch := range model {
		if ch >= '0' && ch <= '9' {
			continue
		}
		if ch >= 'A' && ch <= 'Z' {
			if word != "" {
				words = append(words, word)
				word = ""
			}
		}
		word += string(ch)
	}
	if word != "" {
		words = append(words, word)
	}
	result := ""
	for _, w := range words {
		if result != "" && w != "Mac" && w != "Book" {
			result += " "
		}
		result += w
	}
	return result
}

// macOSDeviceModels is the deduplicated, human-readable model list.
var macOSDeviceModels = func() []string {
	seen := make(map[string]bool)
	var unique []string
	for _, m := range macOSRawDeviceModels {
		name := cleanAndSimplify(macOSFromIdentifier(m))
		if !seen[name] {
			seen[name] = true
			unique = append(unique, name)
		}
	}
	return unique
}()

func randomMacOSDevice(uniqueID string) deviceInfo {
	h := hashStr(uniqueID)
	return deviceInfo{
		model:   macOSDeviceModels[h%uint64(len(macOSDeviceModels))],
		version: macOSSystemVersions[(h/uint64(len(macOSDeviceModels)))%uint64(len(macOSSystemVersions))],
	}
}

