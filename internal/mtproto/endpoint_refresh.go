package mtproto

import (
	"net"
	"strconv"

	"github.com/mtgo-labs/raw/tl"
)

func RefreshEndpoints(table *EndpointTable, config *tl.Config) error {
	if table == nil || config == nil {
		return ErrInvalidEndpoint
	}
	for _, value := range config.DCOptions {
		option, ok := value.(*tl.DCOption)
		if !ok || option.ID <= 0 || option.IPAddress == "" || option.Port <= 0 || option.Port > 65535 || option.MediaOnly || option.CDN || option.TCPOOnly {
			continue
		}
		address := net.JoinHostPort(option.IPAddress, strconv.Itoa(int(option.Port)))
		if existing, exists := table.Get(int(option.ID)); exists {
			if !existing.IPv6 && option.IPv6 {
				continue
			}
		}
		if err := table.Set(DCEndpoint{ID: int(option.ID), Address: address, IPv6: option.IPv6}); err != nil {
			return err
		}
	}
	return nil
}
