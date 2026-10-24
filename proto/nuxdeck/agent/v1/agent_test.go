// SPDX-License-Identifier: Apache-2.0

package agentv1

import (
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func oneofFields(t *testing.T, m proto.Message, name string) map[string]int32 {
	t.Helper()
	o := m.ProtoReflect().Descriptor().Oneofs().ByName(protoreflect.Name(name))
	if o == nil {
		t.Fatalf("%T has no oneof %q", m, name)
	}
	out := map[string]int32{}
	for i := 0; i < o.Fields().Len(); i++ {
		f := o.Fields().Get(i)
		out[string(f.Name())] = int32(f.Number())
	}
	return out
}

// The envelope field numbers are fixed by docs/08-engineering-spec.md and can
// never change once released.
func TestEnvelopeFieldNumbers(t *testing.T) {
	tests := []struct {
		name string
		msg  proto.Message
		want map[string]int32
	}{
		{"AgentMessage", &AgentMessage{}, map[string]int32{
			"hello": 1, "heartbeat": 2, "snapshot": 3, "event": 4, "metrics": 5,
			"log_chunk": 6, "log_ended": 7, "check_result": 8, "renew": 9, "error": 10,
		}},
		{"ServerMessage", &ServerMessage{}, map[string]int32{
			"hello_ack": 1, "open_log": 2, "close_log": 3, "run_check": 4,
			"renew": 5, "config": 6, "disconnect": 7,
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := oneofFields(t, tt.msg, "body")
			if len(got) != len(tt.want) {
				t.Errorf("got %d cases, want %d: %v", len(got), len(tt.want), got)
			}
			for name, num := range tt.want {
				if got[name] != num {
					t.Errorf("%s = %d, want %d", name, got[name], num)
				}
			}
		})
	}
}

func TestEnvelopesReserveActionRange(t *testing.T) {
	for _, m := range []proto.Message{&AgentMessage{}, &ServerMessage{}} {
		ranges := m.ProtoReflect().Descriptor().ReservedRanges()
		found := false
		for i := 0; i < ranges.Len(); i++ {
			r := ranges.Get(i)
			found = found || (r[0] == 100 && r[1] == 200) // end is exclusive
		}
		if !found {
			t.Errorf("%T does not reserve 100 to 199", m)
		}
	}
}

func TestServiceShape(t *testing.T) {
	methods := AgentGateway_ServiceDesc.Methods
	streams := AgentGateway_ServiceDesc.Streams
	if len(methods) != 1 || methods[0].MethodName != "Enroll" {
		t.Errorf("want one unary method Enroll, got %+v", methods)
	}
	if len(streams) != 1 || streams[0].StreamName != "Connect" || !streams[0].ClientStreams || !streams[0].ServerStreams {
		t.Errorf("want one bidirectional stream Connect, got %+v", streams)
	}
}

func TestRoundTrip(t *testing.T) {
	in := &AgentMessage{Body: &AgentMessage_Snapshot{Snapshot: &InventorySnapshot{
		Host: &HostFacts{Hostname: "web-01", CpuCount: 4, Facts: map[string]string{"virt": "kvm"}},
		Containers: []*Container{{
			Runtime: Runtime_RUNTIME_PODMAN, RuntimeId: "abc123", Name: "nginx", State: "running",
			Ports: []*PortMapping{{HostPort: 8080, ContainerPort: 80, Protocol: "tcp"}},
		}},
	}}}
	raw, err := proto.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out AgentMessage
	if err := proto.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(in, &out) {
		t.Errorf("round trip changed the message:\n in: %v\nout: %v", in, &out)
	}
}

// Newer peers may send fields and oneof cases this version does not know; they
// must be ignored, not rejected.
func TestUnknownFieldsAndCasesAreIgnored(t *testing.T) {
	base, err := proto.Marshal(&AgentMessage{Body: &AgentMessage_Heartbeat{Heartbeat: &Heartbeat{SentAtUnixMs: 42}}})
	if err != nil {
		t.Fatal(err)
	}
	withUnknown := protowire.AppendTag(base, 150, protowire.BytesType) // inside the reserved action range
	withUnknown = protowire.AppendString(withUnknown, "from the future")

	var got AgentMessage
	if err := proto.Unmarshal(withUnknown, &got); err != nil {
		t.Fatalf("unknown field rejected: %v", err)
	}
	if got.GetHeartbeat().GetSentAtUnixMs() != 42 {
		t.Errorf("known content lost: %v", &got)
	}

	onlyUnknown := protowire.AppendString(protowire.AppendTag(nil, 99, protowire.BytesType), "new case")
	var server ServerMessage
	if err := proto.Unmarshal(onlyUnknown, &server); err != nil {
		t.Fatalf("unknown oneof case rejected: %v", err)
	}
	if server.GetBody() != nil {
		t.Errorf("unknown case produced a body: %v", server.GetBody())
	}
}

func TestLogLinesCarryRawBytes(t *testing.T) {
	invalidUTF8 := []byte{0xff, 0xfe, 'o', 'k'}
	raw, err := proto.Marshal(&LogChunk{StreamId: "s1", Lines: []*LogLine{{Text: invalidUTF8}}})
	if err != nil {
		t.Fatalf("log lines must tolerate non-UTF-8 output: %v", err)
	}
	var got LogChunk
	if err := proto.Unmarshal(raw, &got); err != nil || string(got.Lines[0].Text) != string(invalidUTF8) {
		t.Errorf("round trip failed: %v %v", err, &got)
	}
}
