package device

import "fmt"

// Auto-generated iOS device models and system versions

var iOSDeviceModels = []struct {
	ID       int
	Suffixes []string
}{
	{5, []string{"S"}},
	{6, []string{" Plus", "", "S", "S Plus"}},
	{7, []string{"", " Plus"}},
	{8, []string{"", " Plus"}},
	{10, []string{"", "S", "S Max", "R"}},
	{11, []string{"", " Pro", " Pro Max"}},
	{12, []string{" mini", "", " Pro", " Pro Max"}},
	{13, []string{" Pro", " Pro Max", " Mini", ""}},
}

var iOSSystemVersions = map[int]map[int][]int{
	15: {2: nil, 1: {1}, 0: {2, 1}},
	14: {8: {1}, 7: {1}, 6: nil, 5: {1}, 4: {2, 1}, 3: nil, 2: {1}, 1: nil, 0: {1}},
	13: {7: nil, 6: {1}, 5: {1}, 4: {1}, 3: {1}, 2: {3, 2}, 1: {3, 2, 1}},
	12: {
		5:  {5, 4, 3, 2, 1},
		4:  {9, 8, 7, 6, 5, 4, 3, 2, 1},
		3:  {2, 1},
		11: {0},
		2:  nil,
		1:  {4, 3, 2, 1},
		0:  {1},
	},
}

func iosAvailableVersions(idModel int) []int {
	switch idModel {
	case 13:
		return []int{15}
	case 12:
		return []int{14, 15}
	case 11:
		return []int{13, 14, 15}
	case 5:
		return []int{12}
	default:
		return []int{12, 13, 14, 15}
	}
}

func initIOSDeviceList() []deviceInfo {
	var list []deviceInfo
	for _, entry := range iOSDeviceModels {
		availableVersions := iosAvailableVersions(entry.ID)
		for _, suffix := range entry.Suffixes {
			var modelStr string
			if entry.ID == 10 {
				modelStr = "iPhone X" + suffix
			} else {
				modelStr = fmt.Sprintf("iPhone %d%s", entry.ID, suffix)
			}
			for _, major := range availableVersions {
				minorMap, ok := iOSSystemVersions[major]
				if !ok {
					continue
				}
				for minor, patches := range minorMap {
					if len(patches) == 0 {
						list = append(list, deviceInfo{model: modelStr, version: fmt.Sprintf("%d.%d", major, minor)})
					} else {
						for _, patch := range patches {
							list = append(list, deviceInfo{model: modelStr, version: fmt.Sprintf("%d.%d.%d", major, minor, patch)})
						}
					}
				}
			}
		}
	}
	return list
}

var iOSDeviceList []deviceInfo

func getIOSDeviceList() []deviceInfo {
	iosOnce.Do(func() {
		iOSDeviceList = initIOSDeviceList()
	})
	return iOSDeviceList
}

func randomIOSDevice(uniqueID string) deviceInfo {
	return hashToValue(hashStr(uniqueID), getIOSDeviceList())
}
