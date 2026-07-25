package session

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	// CurrentVersion is the on-disk session envelope version emitted by Encode.
	CurrentVersion  uint16 = 1
	maxSnapshotSize        = 16 << 20
)

var snapshotMagic = [8]byte{'M', 'T', 'G', 'O', 'R', 'A', 'W', 0}

var (
	ErrUnsupportedVersion = errors.New("session: unsupported snapshot version")
	ErrInvalidSnapshot    = errors.New("session: invalid snapshot")
)

// Snapshot is the versioned state persisted between client runs. Auth keys
// are copied by Encode and Decode; callers retain ownership of their input.
type Snapshot struct {
	APIID         int32     `json:"api_id"`
	PrimaryDC     int       `json:"primary_dc"`
	SessionID     [8]byte   `json:"session_id"`
	AuthKeys      []AuthKey `json:"auth_keys,omitempty"`
	ServerOffset  int64     `json:"server_offset,omitempty"`
	SchemaVersion string    `json:"schema_version,omitempty"`
}

type AuthKey struct {
	DCID       int    `json:"dc_id"`
	Kind       string `json:"kind"`
	Key        []byte `json:"key"`
	ID         uint64 `json:"id"`
	Salt       int64  `json:"salt"`
	TimeOffset int64  `json:"time_offset,omitempty"`
	ExpiresAt  int64  `json:"expires_at,omitempty"`
}

func (snapshot Snapshot) AuthKeyFor(dcid int, kind string) (AuthKey, bool) {
	for _, authKey := range snapshot.AuthKeys {
		if authKey.DCID == dcid && authKey.Kind == kind {
			authKey.Key = append([]byte(nil), authKey.Key...)
			return authKey, true
		}
	}
	return AuthKey{}, false
}

// Encode serializes a snapshot with a fixed magic/version/length envelope.
func Encode(snapshot Snapshot) ([]byte, error) {
	if err := validateSnapshot(snapshot); err != nil {
		return nil, err
	}
	body, err := json.Marshal(snapshot)
	if err != nil {
		return nil, fmt.Errorf("session: encode snapshot: %w", err)
	}
	if len(body) > maxSnapshotSize {
		return nil, fmt.Errorf("%w: payload exceeds %d bytes", ErrInvalidSnapshot, maxSnapshotSize)
	}
	result := make([]byte, 14+len(body))
	copy(result, snapshotMagic[:])
	binary.LittleEndian.PutUint16(result[8:10], CurrentVersion)
	binary.LittleEndian.PutUint32(result[10:14], uint32(len(body)))
	copy(result[14:], body)
	return result, nil
}

// Decode validates and decodes a versioned snapshot. Unknown versions fail
// closed so callers cannot overwrite data they do not understand.
func Decode(data []byte) (Snapshot, error) {
	if len(data) < 14 || len(data) > 14+maxSnapshotSize || !bytes.Equal(data[:8], snapshotMagic[:]) {
		return Snapshot{}, ErrInvalidSnapshot
	}
	version := binary.LittleEndian.Uint16(data[8:10])
	if version != CurrentVersion {
		return Snapshot{}, fmt.Errorf("%w: %d", ErrUnsupportedVersion, version)
	}
	bodyLength := binary.LittleEndian.Uint32(data[10:14])
	if bodyLength > maxSnapshotSize || int(bodyLength) != len(data)-14 {
		return Snapshot{}, ErrInvalidSnapshot
	}
	var snapshot Snapshot
	if err := json.Unmarshal(data[14:], &snapshot); err != nil {
		return Snapshot{}, fmt.Errorf("%w: %v", ErrInvalidSnapshot, err)
	}
	if err := validateSnapshot(snapshot); err != nil {
		return Snapshot{}, err
	}
	for index := range snapshot.AuthKeys {
		snapshot.AuthKeys[index].Key = append([]byte(nil), snapshot.AuthKeys[index].Key...)
	}
	return snapshot, nil
}

func validateSnapshot(snapshot Snapshot) error {
	if snapshot.APIID <= 0 || snapshot.PrimaryDC == 0 {
		return fmt.Errorf("%w: api id and primary dc are required", ErrInvalidSnapshot)
	}
	seen := make(map[string]struct{}, len(snapshot.AuthKeys))
	for _, authKey := range snapshot.AuthKeys {
		if authKey.DCID == 0 || authKey.Kind == "" || len(authKey.Key) != 256 || authKey.ID == 0 {
			return fmt.Errorf("%w: invalid auth key", ErrInvalidSnapshot)
		}
		key := fmt.Sprintf("%d:%s", authKey.DCID, authKey.Kind)
		if _, ok := seen[key]; ok {
			return fmt.Errorf("%w: duplicate auth key", ErrInvalidSnapshot)
		}
		seen[key] = struct{}{}
	}
	return nil
}
