package naming

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/mtgo-labs/raw/cmd/tlgen/internal/schema"
)

func TestEntry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		entry  schema.Entry
		flavor Flavor
		want   string
	}{
		{"constructor", schema.Entry{Name: "user", Kind: schema.KindClass}, API, "User"},
		{"empty constructor", schema.Entry{Name: "userEmpty", Kind: schema.KindClass}, API, "UserEmpty"},
		{"method", schema.Entry{Name: "messages.getHistory", Kind: schema.KindMethod}, API, "MessagesGetHistoryRequest"},
		{"synthetic constructor", schema.Entry{Name: "mtcute.dummyUpdate", Kind: schema.KindClass}, API, "SyntheticDummyUpdate"},
		{"synthetic method", schema.Entry{Name: "mtcute.customMethod", Kind: schema.KindMethod}, API, "SyntheticCustomMethodRequest"},
		{"numbered ID", schema.Entry{Name: "inputBotInlineMessageID64", Kind: schema.KindClass}, API, "InputBotInlineMessageID64"},
		{"HTML", schema.Entry{Name: "inputRichMessageHTML", Kind: schema.KindClass}, API, "InputRichMessageHTML"},
		{"JPEG", schema.Entry{Name: "storage.fileJpeg", Kind: schema.KindClass}, API, "StorageFileJPEG"},
		{"RTMP URL", schema.Entry{Name: "phone.groupCallStreamRtmpUrl", Kind: schema.KindClass}, API, "PhoneGroupCallStreamRTMPURL"},
		{"MTP constructor", schema.Entry{Name: "mt_rpc_result", Kind: schema.KindClass}, MTP, "MTPRPCResult"},
		{"MTP PQ", schema.Entry{Name: "mt_p_q_inner_data", Kind: schema.KindClass}, MTP, "MTPPQInnerData"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := Entry(&tc.entry, tc.flavor)
			if err != nil {
				t.Fatalf("Entry: %v", err)
			}
			if got != tc.want {
				t.Fatalf("Entry() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestUnion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		flavor Flavor
		want   string
	}{
		{"User", API, "UserClass"},
		{"messages.Messages", API, "MessagesMessagesClass"},
		{"mtcute.Value", API, "SyntheticValueClass"},
		{"RpcDropAnswer", MTP, "MTPRPCDropAnswerClass"},
	}
	for _, tc := range tests {
		got, err := Union(tc.name, tc.flavor)
		if err != nil {
			t.Fatalf("Union(%q): %v", tc.name, err)
		}
		if got != tc.want {
			t.Fatalf("Union(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestField(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"api_id":        "APIID",
		"callback_url":  "CallbackURL",
		"dc_id":         "DCID",
		"msg_id":        "MessageID",
		"msg_ids":       "MessageIDs",
		"ipv6":          "IPv6",
		"json_data":     "JSONData",
		"native_ui":     "NativeUI",
		"other_uids":    "OtherUIDs",
		"public_key":    "PublicKey",
		"queryId":       "QueryID",
		"rtmp_stream":   "RTMPStream",
		"tcp_optimized": "TCPOptimized",
		"tcpo_only":     "TCPOOnly",
		"udp_p2p":       "UDPP2P",
	}
	for input, want := range tests {
		got, err := Field(input)
		if err != nil {
			t.Fatalf("Field(%q): %v", input, err)
		}
		if got != want {
			t.Fatalf("Field(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestAuditPinnedSchemas(t *testing.T) {
	t.Parallel()

	api, err := schema.LoadAPI(projectPath("schema", "api-schema.json"))
	if err != nil {
		t.Fatalf("LoadAPI: %v", err)
	}
	mtp, err := schema.LoadMTP(projectPath("schema", "mtp-schema.json"))
	if err != nil {
		t.Fatalf("LoadMTP: %v", err)
	}
	if err := Audit(api, mtp); err != nil {
		t.Fatalf("Audit: %v", err)
	}
}

func TestAuditRejectsCollision(t *testing.T) {
	t.Parallel()

	api := &schema.Schema{
		Entries: []schema.Entry{
			{Kind: schema.KindClass, Name: "apiValue"},
			{Kind: schema.KindClass, Name: "APIValue"},
		},
		Unions: map[string]*schema.Union{},
	}
	err := Audit(api, &schema.Schema{Unions: map[string]*schema.Union{}})
	if err == nil || !strings.Contains(err.Error(), "both normalize") {
		t.Fatalf("Audit error = %v, want collision", err)
	}
}

func TestFieldRejectsUnsupportedCharacter(t *testing.T) {
	t.Parallel()

	if _, err := Field("bad$value"); err == nil {
		t.Fatal("Field succeeded, want error")
	}
}

func TestFieldRejectsEmptyWord(t *testing.T) {
	t.Parallel()

	for _, input := range []string{"_value", "value_", "bad__value"} {
		if _, err := Field(input); err == nil {
			t.Errorf("Field(%q) succeeded, want error", input)
		}
	}
}

func TestEntryRejectsUnknownFlavor(t *testing.T) {
	t.Parallel()

	entry := &schema.Entry{Name: "user", Kind: schema.KindClass}
	if _, err := Entry(entry, Flavor(255)); err == nil {
		t.Fatal("Entry succeeded, want error")
	}
}

func projectPath(parts ...string) string {
	all := append([]string{"..", "..", "..", ".."}, parts...)
	return filepath.Join(all...)
}
