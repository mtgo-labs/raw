package device

// Auto-generated Linux device data

var linuxSystemVersions = func() []string {
	var result []string
	for _, env := range []string{"GNOME", "MATE", "XFCE", "Cinnamon", "Unity", "ubuntu", "LXDE"} {
		for _, wl := range []string{"Wayland", "XWayland", "X11"} {
			for _, lv := range []string{"2.31", "2.32", "2.33", "2.34"} {
				result = append(result, "Linux "+env+" "+wl+" glibc "+lv)
			}
		}
	}
	return result
}()

func randomLinuxDevice(uniqueID string) deviceInfo {
	h := hashStr(uniqueID)
	models := cleanedDesktopModels
	return deviceInfo{
		model:   models[h%uint64(len(models))],
		version: linuxSystemVersions[(h/uint64(len(models)))%uint64(len(linuxSystemVersions))],
	}
}
