package session

import (
	"encoding/binary"
	"net"
)

func decodePyrogramSessionString(payload []byte) (SessionString, error) {
	var dcid int
	var apiID int32
	var testMode byte
	var authKey []byte
	var userID uint64
	var bot byte
	switch len(payload) {
	case 263:
		dcid = int(payload[0])
		testMode = payload[1]
		authKey = payload[2:258]
		userID = uint64(binary.BigEndian.Uint32(payload[258:262]))
		bot = payload[262]
	case 267:
		dcid = int(payload[0])
		testMode = payload[1]
		authKey = payload[2:258]
		userID = binary.BigEndian.Uint64(payload[258:266])
		bot = payload[266]
	case 271:
		dcid = int(payload[0])
		apiID = int32(binary.BigEndian.Uint32(payload[1:5]))
		testMode = payload[5]
		authKey = payload[6:262]
		userID = binary.BigEndian.Uint64(payload[262:270])
		bot = payload[270]
	default:
		return SessionString{}, ErrInvalidSessionString
	}
	if dcid <= 0 || dcid > 5 || testMode > 1 || bot > 1 || apiID < 0 || userID > maxInt53 || userID == 0 && bot != 0 {
		return SessionString{}, ErrInvalidSessionString
	}
	address, ok := sessionStringDefaultAddress(dcid, testMode != 0)
	if !ok {
		return SessionString{}, ErrInvalidSessionString
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return SessionString{}, ErrInvalidSessionString
	}
	main := SessionStringDC{
		ID:       dcid,
		Address:  address,
		IPv6:     net.ParseIP(host).To4() == nil,
		TestMode: testMode != 0,
	}
	var user *SessionStringUser
	if userID != 0 {
		user = &SessionStringUser{ID: int64(userID), Bot: bot != 0}
	}
	return SessionString{
		Format:        SessionStringFormatPyrogram,
		APIID:         apiID,
		Main:          main,
		Media:         main,
		User:          user,
		AuthKey:       append([]byte(nil), authKey...),
		AddressKnown:  false,
		TestModeKnown: true,
	}, nil
}
