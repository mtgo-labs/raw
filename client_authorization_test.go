package raw

import (
	"bytes"
	"context"
	"crypto/sha1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mtgo-labs/raw/internal/cryptoutil"
	"github.com/mtgo-labs/raw/internal/mtproto"
	"github.com/mtgo-labs/raw/internal/transport"
	"github.com/mtgo-labs/raw/session"
	"github.com/mtgo-labs/raw/tl"
)

var testRSAFingerprint = uint64(0xb25898df208d2603)

type incrementReader struct {
	next byte
}

func (reader *incrementReader) Read(output []byte) (int, error) {
	for index := range output {
		output[index] = reader.next
		reader.next++
	}
	if len(output) == 256 {
		output[0] &= 0x3f
	}
	return len(output), nil
}

type countingStore struct {
	*session.MemoryStore
	saves atomic.Int32
	err   error
}

func (store *countingStore) Save(ctx context.Context, data []byte) error {
	store.saves.Add(1)
	if store.err != nil {
		return store.err
	}
	return store.MemoryStore.Save(ctx, data)
}

func TestClientConnectNegotiatesAndPersistsPermanentAuthKey(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	fixedNow := time.Unix(1_700_000_000, 123_000_000)
	release := make(chan struct{})
	serverDone := make(chan authorizationServerResult, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverDone <- authorizationServerResult{err: err}
			return
		}
		key, err := runAuthorizationServer(connection, fixedNow, release)
		serverDone <- authorizationServerResult{key: key, err: err}
	}()

	store := &countingStore{MemoryStore: session.NewMemoryStore()}
	client, err := NewClient(Config{APIID: 1, DCID: 2, Address: listener.Addr().String(), Store: store})
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return fixedNow }
	client.authRandom = &incrementReader{}
	if err := client.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if store.saves.Load() != 1 {
		t.Fatalf("authorization saves = %d, want 1", store.saves.Load())
	}
	data, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := session.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.AuthKeys) != 1 || snapshot.AuthKeys[0].ID == 0 || len(snapshot.AuthKeys[0].Key) != 256 {
		t.Fatalf("persisted snapshot = %+v", snapshot)
	}
	if client.session == nil || client.permanent.key.ID != snapshot.AuthKeys[0].ID {
		t.Fatal("negotiated key was not activated")
	}

	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	close(release)
	result := <-serverDone
	if result.err != nil {
		t.Fatal(result.err)
	}
	if result.key.ID != snapshot.AuthKeys[0].ID || !bytes.Equal(result.key.Key[:], snapshot.AuthKeys[0].Key) {
		t.Fatal("client and server derived different authorization keys")
	}
}

func TestClientConnectRejectsAuthorizationStorageFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	fixedNow := time.Unix(1_700_000_000, 123_000_000)
	serverDone := make(chan authorizationServerResult, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverDone <- authorizationServerResult{err: err}
			return
		}
		key, err := runAuthorizationServer(connection, fixedNow, nil)
		serverDone <- authorizationServerResult{key: key, err: err}
	}()

	saveErr := errors.New("save failed")
	store := &countingStore{MemoryStore: session.NewMemoryStore(), err: saveErr}
	client, err := NewClient(Config{APIID: 1, DCID: 2, Address: listener.Addr().String(), Store: store})
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return fixedNow }
	client.authRandom = &incrementReader{}
	if err := client.Connect(context.Background()); !errors.Is(err, saveErr) {
		t.Fatalf("Connect error = %v, want %v", err, saveErr)
	}
	if store.saves.Load() != 1 || client.session != nil || client.conn != nil || client.permanent.key.ID != 0 {
		t.Fatal("failed authorization was activated or persisted more than once")
	}
	if result := <-serverDone; result.err != nil {
		t.Fatal(result.err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestClientConnectCancelsAuthorization(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			accepted <- connection
		}
	}()
	store := &countingStore{MemoryStore: session.NewMemoryStore()}
	client, err := NewClient(Config{APIID: 1, DCID: 2, Address: listener.Addr().String(), Store: store})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if err := client.Connect(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Connect error = %v, want context deadline", err)
	}
	connection := <-accepted
	_ = connection.Close()
	if store.saves.Load() != 0 || client.session != nil || client.conn != nil {
		t.Fatal("cancelled authorization changed client state")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}

type authorizationServerResult struct {
	key mtproto.AuthKey
	err error
}

func runAuthorizationServer(connection net.Conn, now time.Time, release <-chan struct{}) (mtproto.AuthKey, error) {
	defer connection.Close()
	var header [4]byte
	if _, err := io.ReadFull(connection, header[:]); err != nil {
		return mtproto.AuthKey{}, err
	}
	if header != [4]byte{0xee, 0xee, 0xee, 0xee} {
		return mtproto.AuthKey{}, fmt.Errorf("packet header = %x", header)
	}
	packet, err := transport.NewPacketConn(connection, transport.PacketIntermediate)
	if err != nil {
		return mtproto.AuthKey{}, err
	}

	object, _, err := mtproto.ReceivePlainObject(packet, 4096)
	if err != nil {
		return mtproto.AuthKey{}, err
	}
	reqPQ, ok := object.(*tl.MTPReqPQMulti)
	if !ok {
		return mtproto.AuthKey{}, fmt.Errorf("first request = %T", object)
	}
	var serverNonce [16]byte
	for index := range serverNonce {
		serverNonce[index] = byte(0xa0 + index)
	}
	if _, err := mtproto.SendPlainObject(packet, now.Add(time.Second), &tl.MTPResPQ{
		Nonce:                       reqPQ.Nonce,
		ServerNonce:                 serverNonce,
		PQ:                          []byte{15},
		ServerPublicKeyFingerprints: []int64{int64(testRSAFingerprint)},
	}); err != nil {
		return mtproto.AuthKey{}, err
	}

	object, _, err = mtproto.ReceivePlainObject(packet, 4096)
	if err != nil {
		return mtproto.AuthKey{}, err
	}
	reqDH, ok := object.(*tl.MTPReqDHParams)
	if !ok || reqDH.Nonce != reqPQ.Nonce || reqDH.ServerNonce != serverNonce ||
		!bytes.Equal(reqDH.P, []byte{3}) || !bytes.Equal(reqDH.Q, []byte{5}) ||
		uint64(reqDH.PublicKeyFingerprint) != testRSAFingerprint || len(reqDH.EncryptedData) != 256 {
		return mtproto.AuthKey{}, fmt.Errorf("req_DH_params = %+v", object)
	}

	var newNonce [32]byte
	for index := range newNonce {
		newNonce[index] = byte(index + 16)
	}
	prime := cryptoutil.TelegramDHPrime()
	serverExponent := new(big.Int).SetBytes(bytes.Repeat([]byte{0x35}, 256))
	ga := new(big.Int).Exp(big.NewInt(4), serverExponent, prime)
	serverTime := int32(now.Unix() + 123)
	encryptedAnswer, err := encryptServerDHAnswer(serverNonce, newNonce, &tl.MTPServerDHInnerData{
		Nonce: reqPQ.Nonce, ServerNonce: serverNonce, G: 4, DHPrime: prime.Bytes(), GA: ga.Bytes(), ServerTime: serverTime,
	})
	if err != nil {
		return mtproto.AuthKey{}, err
	}
	if _, err := mtproto.SendPlainObject(packet, now.Add(2*time.Second), &tl.MTPServerDHParamsOk{
		Nonce: reqPQ.Nonce, ServerNonce: serverNonce, EncryptedAnswer: encryptedAnswer,
	}); err != nil {
		return mtproto.AuthKey{}, err
	}

	object, _, err = mtproto.ReceivePlainObject(packet, 4096)
	if err != nil {
		return mtproto.AuthKey{}, err
	}
	setClientDH, ok := object.(*tl.MTPSetClientDHParams)
	if !ok || setClientDH.Nonce != reqPQ.Nonce || setClientDH.ServerNonce != serverNonce {
		return mtproto.AuthKey{}, fmt.Errorf("set_client_DH_params = %+v", object)
	}
	firstInner, firstAuthKey, err := deriveServerAuthKey(serverNonce, newNonce, setClientDH.EncryptedData, serverExponent, prime, int64(serverTime), now)
	if err != nil {
		return mtproto.AuthKey{}, err
	}
	if firstInner.RetryID != 0 {
		return mtproto.AuthKey{}, fmt.Errorf("initial retry ID = %d", firstInner.RetryID)
	}
	if _, err := mtproto.SendPlainObject(packet, now.Add(3*time.Second), &tl.MTPDHGenRetry{
		Nonce: reqPQ.Nonce, ServerNonce: serverNonce, NewNonceHash2: mtproto.NewNonceHash(newNonce, 2, firstAuthKey.AuxHash),
	}); err != nil {
		return mtproto.AuthKey{}, err
	}

	object, _, err = mtproto.ReceivePlainObject(packet, 4096)
	if err != nil {
		return mtproto.AuthKey{}, err
	}
	setClientDH, ok = object.(*tl.MTPSetClientDHParams)
	if !ok || setClientDH.Nonce != reqPQ.Nonce || setClientDH.ServerNonce != serverNonce {
		return mtproto.AuthKey{}, fmt.Errorf("retried set_client_DH_params = %+v", object)
	}
	secondInner, authKey, err := deriveServerAuthKey(serverNonce, newNonce, setClientDH.EncryptedData, serverExponent, prime, int64(serverTime), now)
	if err != nil {
		return mtproto.AuthKey{}, err
	}
	if secondInner.RetryID != int64(firstAuthKey.AuxHash) {
		return mtproto.AuthKey{}, fmt.Errorf("retried ID = %d, want %d", secondInner.RetryID, int64(firstAuthKey.AuxHash))
	}
	if _, err := mtproto.SendPlainObject(packet, now.Add(4*time.Second), &tl.MTPDHGenOk{
		Nonce: reqPQ.Nonce, ServerNonce: serverNonce, NewNonceHash1: mtproto.NewNonceHash(newNonce, 1, authKey.AuxHash),
	}); err != nil {
		return mtproto.AuthKey{}, err
	}
	if release != nil {
		<-release
	}
	return authKey, nil
}

func deriveServerAuthKey(
	serverNonce [16]byte,
	newNonce [32]byte,
	encrypted []byte,
	serverExponent, prime *big.Int,
	serverTime int64,
	now time.Time,
) (*tl.MTPClientDHInnerData, mtproto.AuthKey, error) {
	clientDH, err := decryptClientDH(serverNonce, newNonce, encrypted)
	if err != nil {
		return nil, mtproto.AuthKey{}, err
	}
	shared := new(big.Int).Exp(new(big.Int).SetBytes(clientDH.GB), serverExponent, prime)
	sharedBytes := make([]byte, 256)
	shared.FillBytes(sharedBytes)
	authKey, err := mtproto.NewAuthKey(sharedBytes, serverNonce, newNonce, serverTime, now)
	clear(sharedBytes)
	if err != nil {
		return nil, mtproto.AuthKey{}, err
	}
	return clientDH, authKey, nil
}

func encryptServerDHAnswer(serverNonce [16]byte, newNonce [32]byte, inner tl.Object) ([]byte, error) {
	encoded, err := tl.Encode(inner)
	if err != nil {
		return nil, err
	}
	digest := sha1.Sum(encoded)
	plain := make([]byte, sha1.Size+len(encoded), sha1.Size+len(encoded)+15)
	copy(plain, digest[:])
	copy(plain[sha1.Size:], encoded)
	plain = append(plain, make([]byte, (16-len(plain)%16)%16)...)
	key, iv := cryptoutil.DeriveNonceAESKeyIV(serverNonce, newNonce)
	block, err := cryptoutil.NewAES256(key[:])
	if err != nil {
		return nil, err
	}
	if err := cryptoutil.EncryptIGE(plain, plain, block, iv[:]); err != nil {
		return nil, err
	}
	return plain, nil
}

func decryptClientDH(serverNonce [16]byte, newNonce [32]byte, encrypted []byte) (*tl.MTPClientDHInnerData, error) {
	plain := bytes.Clone(encrypted)
	key, iv := cryptoutil.DeriveNonceAESKeyIV(serverNonce, newNonce)
	block, err := cryptoutil.NewAES256(key[:])
	if err != nil {
		return nil, err
	}
	if err := cryptoutil.DecryptIGE(plain, plain, block, iv[:]); err != nil {
		return nil, err
	}
	for end := len(plain); end >= sha1.Size+4; end -= 4 {
		object, err := tl.Decode(plain[sha1.Size:end], tl.DefaultDecodeLimits())
		if err != nil {
			continue
		}
		inner, ok := object.(*tl.MTPClientDHInnerData)
		if !ok {
			continue
		}
		digest := sha1.Sum(plain[sha1.Size:end])
		if bytes.Equal(digest[:], plain[:sha1.Size]) {
			return inner, nil
		}
	}
	return nil, errors.New("invalid client_DH_inner_data")
}
