package raw

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/mtgo-labs/raw/internal/cryptoutil"
	"github.com/mtgo-labs/raw/internal/mtproto"
	"github.com/mtgo-labs/raw/internal/transport"
	"github.com/mtgo-labs/raw/tl"
)

func TestRequestLocalMigrationPreservesRequestAndOrdering(t *testing.T) {
	client, primaryServer, targetServer, primaryKey, targetKey, targetSessionID := newMigrationTranscriptClient(t)
	const orderingKey = "migration-order"
	client.mu.Lock()
	client.routes[routeKey{dcid: 4, kind: ConnectionMain}].ordering = map[string]uint64{orderingKey: 42}
	client.mu.Unlock()

	primaryDone := make(chan error, 1)
	go func() {
		messageID, body, err := readClientRequest(primaryServer, primaryKey, [8]byte{2})
		if err == nil && binary.LittleEndian.Uint32(body) != tl.HelpGetConfigRequestConstructorID {
			err = fmt.Errorf("primary constructor=%#x", binary.LittleEndian.Uint32(body))
		}
		if err == nil {
			err = writeServerResult(primaryServer, primaryKey, [8]byte{2}, messageID, &tl.MTPRPCError{
				ErrorCode: 303, ErrorMessage: "FILE_MIGRATE_4",
			})
		}
		primaryDone <- err
	}()

	targetDone := make(chan error, 1)
	go func() {
		messageID, body, err := readClientRequest(targetServer, targetKey, targetSessionID)
		if err == nil && len(body) < 16 {
			err = fmt.Errorf("target request length=%d", len(body))
		}
		if err == nil && binary.LittleEndian.Uint32(body) != tl.InvokeAfterMessageRequestConstructorID {
			err = fmt.Errorf("target constructor=%#x", binary.LittleEndian.Uint32(body))
		}
		if err == nil && binary.LittleEndian.Uint64(body[4:]) != 42 {
			err = fmt.Errorf("target ordering message=%d", binary.LittleEndian.Uint64(body[4:]))
		}
		if err == nil && binary.LittleEndian.Uint32(body[12:]) != tl.HelpGetConfigRequestConstructorID {
			err = fmt.Errorf("target nested constructor=%#x", binary.LittleEndian.Uint32(body[12:]))
		}
		if err == nil {
			err = writeServerResult(targetServer, targetKey, targetSessionID, messageID, &tl.Config{})
		}
		targetDone <- err
	}()

	result, err := invokeWithMigration(
		context.Background(),
		client,
		&tl.HelpGetConfigRequest{},
		InvokeOptions{OrderingKey: orderingKey},
	)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("migration returned a nil typed result")
	}
	if err := <-primaryDone; err != nil {
		t.Fatal(err)
	}
	if err := <-targetDone; err != nil {
		t.Fatal(err)
	}
	client.mu.Lock()
	_, remains := client.routes[routeKey{dcid: 4, kind: ConnectionMain}].ordering[orderingKey]
	client.mu.Unlock()
	if remains {
		t.Fatal("completed migration ordering state remained registered")
	}
}

func TestRequestLocalMigrationPreservesContextCancellation(t *testing.T) {
	client, primaryServer, targetServer, primaryKey, targetKey, targetSessionID := newMigrationTranscriptClient(t)
	primaryDone := make(chan error, 1)
	go func() {
		messageID, _, err := readClientRequest(primaryServer, primaryKey, [8]byte{2})
		if err == nil {
			err = writeServerResult(primaryServer, primaryKey, [8]byte{2}, messageID, &tl.MTPRPCError{
				ErrorCode: 303, ErrorMessage: "FILE_MIGRATE_4",
			})
		}
		primaryDone <- err
	}()

	targetReceived := make(chan error, 1)
	go func() {
		_, body, err := readClientRequest(targetServer, targetKey, targetSessionID)
		if err == nil && binary.LittleEndian.Uint32(body) != tl.HelpGetConfigRequestConstructorID {
			err = fmt.Errorf("target constructor=%#x", binary.LittleEndian.Uint32(body))
		}
		targetReceived <- err
	}()

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := invokeWithMigration(ctx, client, &tl.HelpGetConfigRequest{}, InvokeOptions{})
		result <- err
	}()
	if err := <-targetReceived; err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("migration cancellation err=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("migrated request ignored context cancellation")
	}
	if err := <-primaryDone; err != nil {
		t.Fatal(err)
	}
}

func TestIndependentDCRoutesDoNotSerializeRequests(t *testing.T) {
	client, primaryServer, targetServer, primaryKey, targetKey, targetSessionID := newMigrationTranscriptClient(t)
	primaryReceived := make(chan struct{})
	releasePrimary := make(chan struct{})
	primaryServerDone := make(chan error, 1)
	go func() {
		messageID, _, err := readClientRequest(primaryServer, primaryKey, [8]byte{2})
		if err == nil {
			close(primaryReceived)
			<-releasePrimary
			err = writeServerResult(primaryServer, primaryKey, [8]byte{2}, messageID, &tl.Config{})
		}
		primaryServerDone <- err
	}()

	targetServerDone := make(chan error, 1)
	go func() {
		messageID, _, err := readClientRequest(targetServer, targetKey, targetSessionID)
		if err == nil {
			err = writeServerResult(targetServer, targetKey, targetSessionID, messageID, &tl.Config{})
		}
		targetServerDone <- err
	}()

	primaryResult := make(chan error, 1)
	go func() {
		_, err := invokeRoute(context.Background(), client, &tl.HelpGetConfigRequest{}, InvokeOptions{})
		primaryResult <- err
	}()
	select {
	case <-primaryReceived:
	case <-time.After(time.Second):
		t.Fatal("primary request was not sent")
	}

	targetResult := make(chan error, 1)
	go func() {
		_, err := invokeRoute(context.Background(), client, &tl.HelpGetConfigRequest{}, InvokeOptions{DCID: 4})
		targetResult <- err
	}()
	select {
	case err := <-targetResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("target DC request serialized behind primary DC")
	}
	close(releasePrimary)
	if err := <-primaryResult; err != nil {
		t.Fatal(err)
	}
	if err := <-primaryServerDone; err != nil {
		t.Fatal(err)
	}
	if err := <-targetServerDone; err != nil {
		t.Fatal(err)
	}
}

func newMigrationTranscriptClient(t *testing.T) (*Client, net.Conn, net.Conn, mtproto.AuthKey, mtproto.AuthKey, [8]byte) {
	t.Helper()
	client, err := NewClient(Config{
		APIID: 1, Address: "127.0.0.1:1", PoolIdleTimeout: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	primaryClient, primaryServer := net.Pipe()
	targetClient, targetServer := net.Pipe()
	primaryKey, targetKey := testAuthKey(2), testAuthKey(4)
	primarySessionID, targetSessionID := [8]byte{2}, [8]byte{4}
	primarySession := mtproto.NewSession(primaryKey, 0, primarySessionID, 4)
	targetSession := mtproto.NewSession(targetKey, 0, targetSessionID, 4)
	targetRouteKey := routeKey{dcid: 4, kind: ConnectionMain}
	targetRoute := &clientRoute{connection: targetClient, session: targetSession}

	client.mu.Lock()
	client.conn = primaryClient
	client.session = primarySession
	client.permanent = authState{key: primaryKey, sessionID: primarySessionID}
	client.initConnectionDone = true
	targetRoute.initConnectionDone = true
	client.routes[targetRouteKey] = targetRoute
	client.startReceiveRouteLocked(
		routeKey{dcid: client.config.DCID, kind: ConnectionMain},
		&clientRoute{connection: primaryClient, session: primarySession},
	)
	client.startReceiveRouteLocked(targetRouteKey, targetRoute)
	client.mu.Unlock()

	t.Cleanup(func() {
		_ = primaryServer.Close()
		_ = targetServer.Close()
	})
	t.Cleanup(func() {
		_ = client.Close()
	})
	return client, primaryServer, targetServer, primaryKey, targetKey, targetSessionID
}

func readClientRequest(connection net.Conn, key mtproto.AuthKey, sessionID [8]byte) (uint64, []byte, error) {
	payload, err := transport.ReadIntermediate(connection, 1<<20)
	if err != nil {
		return 0, nil, err
	}
	if len(payload) < 56 || binary.LittleEndian.Uint64(payload) != key.ID {
		return 0, nil, errors.New("invalid client encrypted payload")
	}
	var messageKey [16]byte
	copy(messageKey[:], payload[8:24])
	plain := append([]byte(nil), payload[24:]...)
	block, iv, err := cryptoutil.NewMessageAES256(key.Key[:], messageKey, cryptoutil.ClientToServer)
	if err != nil {
		return 0, nil, err
	}
	if err := cryptoutil.DecryptIGE(plain, plain, block, iv[:]); err != nil {
		return 0, nil, err
	}
	computed, err := cryptoutil.ComputeMessageKey(key.Key[:], plain, cryptoutil.ClientToServer)
	if err != nil || !bytes.Equal(computed[:], messageKey[:]) {
		return 0, nil, errors.New("invalid client message key")
	}
	if !bytes.Equal(plain[8:16], sessionID[:]) {
		return 0, nil, errors.New("invalid client session ID")
	}
	bodyLength := int(binary.LittleEndian.Uint32(plain[28:32]))
	if bodyLength < 4 || bodyLength > len(plain)-32 {
		return 0, nil, errors.New("invalid client body length")
	}
	return binary.LittleEndian.Uint64(plain[16:24]), plain[32 : 32+bodyLength], nil
}

func writeServerResult(connection net.Conn, key mtproto.AuthKey, sessionID [8]byte, requestMessageID uint64, result tl.Object) error {
	return writeServerObject(
		connection,
		key,
		0,
		sessionID,
		requestMessageID+1,
		&tl.MTPRPCResult{ReqMessageID: int64(requestMessageID), Result: result},
	)
}

func writeServerBody(connection net.Conn, key mtproto.AuthKey, salt int64, sessionID [8]byte, messageID uint64, body []byte) error {
	padding := 12
	for (32+len(body)+padding)%16 != 0 {
		padding++
	}
	plain := make([]byte, 32+len(body)+padding)
	binary.LittleEndian.PutUint64(plain, uint64(salt))
	copy(plain[8:16], sessionID[:])
	binary.LittleEndian.PutUint64(plain[16:24], messageID)
	binary.LittleEndian.PutUint32(plain[24:28], 1)
	binary.LittleEndian.PutUint32(plain[28:32], uint32(len(body)))
	copy(plain[32:], body)
	for index := 32 + len(body); index < len(plain); index++ {
		plain[index] = 7
	}
	messageKey, err := cryptoutil.ComputeMessageKey(key.Key[:], plain, cryptoutil.ServerToClient)
	if err != nil {
		return err
	}
	block, iv, err := cryptoutil.NewMessageAES256(key.Key[:], messageKey, cryptoutil.ServerToClient)
	if err != nil {
		return err
	}
	ciphertext := append([]byte(nil), plain...)
	if err := cryptoutil.EncryptIGE(ciphertext, ciphertext, block, iv[:]); err != nil {
		return err
	}
	payload := make([]byte, 24+len(ciphertext))
	binary.LittleEndian.PutUint64(payload, key.ID)
	copy(payload[8:24], messageKey[:])
	copy(payload[24:], ciphertext)
	return transport.WriteIntermediate(connection, payload)
}

func writeServerResultRaw(connection net.Conn, key mtproto.AuthKey, sessionID [8]byte, requestMessageID uint64, resultBody []byte) error {
	body := make([]byte, 12+len(resultBody))
	binary.LittleEndian.PutUint32(body, tl.MTPRPCResultConstructorID)
	binary.LittleEndian.PutUint64(body[4:], requestMessageID)
	copy(body[12:], resultBody)
	return writeServerBody(connection, key, 0, sessionID, requestMessageID+1, body)
}

func writeServerObject(connection net.Conn, key mtproto.AuthKey, salt int64, sessionID [8]byte, messageID uint64, object tl.Object) error {
	body, err := tl.Encode(object)
	if err != nil {
		return err
	}
	padding := 12
	for (32+len(body)+padding)%16 != 0 {
		padding++
	}
	plain := make([]byte, 32+len(body)+padding)
	binary.LittleEndian.PutUint64(plain, uint64(salt))
	copy(plain[8:16], sessionID[:])
	binary.LittleEndian.PutUint64(plain[16:24], messageID)
	binary.LittleEndian.PutUint32(plain[24:28], 1)
	binary.LittleEndian.PutUint32(plain[28:32], uint32(len(body)))
	copy(plain[32:], body)
	for index := 32 + len(body); index < len(plain); index++ {
		plain[index] = 7
	}
	messageKey, err := cryptoutil.ComputeMessageKey(key.Key[:], plain, cryptoutil.ServerToClient)
	if err != nil {
		return err
	}
	block, iv, err := cryptoutil.NewMessageAES256(key.Key[:], messageKey, cryptoutil.ServerToClient)
	if err != nil {
		return err
	}
	ciphertext := append([]byte(nil), plain...)
	if err := cryptoutil.EncryptIGE(ciphertext, ciphertext, block, iv[:]); err != nil {
		return err
	}
	payload := make([]byte, 24+len(ciphertext))
	binary.LittleEndian.PutUint64(payload, key.ID)
	copy(payload[8:24], messageKey[:])
	copy(payload[24:], ciphertext)
	return transport.WriteIntermediate(connection, payload)
}
