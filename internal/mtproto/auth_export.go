package mtproto

import (
	"encoding/binary"
	"errors"
)

var (
	ErrInvalidAuthExport = errors.New("mtproto: invalid auth export")
	authExportMagic      = [8]byte{'M', 'T', 'G', 'O', 'A', 'U', 'T', 0}
)

type AuthExport struct {
	DCID      int
	AuthKey   AuthKey
	Salt      int64
	SessionID [8]byte
}

func EncodeAuthExport(export AuthExport) ([]byte, error) {
	if export.DCID <= 0 || export.AuthKey.ID == 0 {
		return nil, ErrInvalidAuthExport
	}
	result := make([]byte, 8+2+2+8+8+8+256)
	copy(result, authExportMagic[:])
	binary.LittleEndian.PutUint16(result[8:10], 1)
	binary.LittleEndian.PutUint16(result[10:12], uint16(export.DCID))
	binary.LittleEndian.PutUint64(result[12:20], export.AuthKey.ID)
	binary.LittleEndian.PutUint64(result[20:28], uint64(export.Salt))
	copy(result[28:36], export.SessionID[:])
	copy(result[36:], export.AuthKey.Key[:])
	return result, nil
}

func DecodeAuthExport(data []byte) (AuthExport, error) {
	if len(data) != 292 || string(data[:8]) != string(authExportMagic[:]) || binary.LittleEndian.Uint16(data[8:10]) != 1 {
		return AuthExport{}, ErrInvalidAuthExport
	}
	export := AuthExport{DCID: int(binary.LittleEndian.Uint16(data[10:12]))}
	export.AuthKey.ID = binary.LittleEndian.Uint64(data[12:20])
	export.Salt = int64(binary.LittleEndian.Uint64(data[20:28]))
	copy(export.SessionID[:], data[28:36])
	copy(export.AuthKey.Key[:], data[36:])
	if export.DCID <= 0 || export.AuthKey.ID == 0 {
		return AuthExport{}, ErrInvalidAuthExport
	}
	return export, nil
}
