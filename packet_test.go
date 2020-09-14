package nbns

import (
	"bytes"
	"testing"
)

func Test_encodeNBNSName(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		// TODO: Add test cases.
		{name: "test FRED",
			args: args{name: "FRED"},
			want: " EGFCEFEECACACACACACACACACACACACA\x00",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := encodeNBNSName(tt.args.name); got != tt.want {
				t.Errorf("encodeNBNSName() =|%x|%v, want |%x|%v", got, len(got), tt.want, len(tt.want))
			}
		})
	}
}

func Test_decodeNBNSName(t *testing.T) {
	type args struct {
		buffer *bytes.Buffer
	}
	tests := []struct {
		name     string
		args     args
		wantName string
	}{
		{name: "test FRED",
			args:     args{buffer: bytes.NewBuffer([]byte(" EGFCEFEECACACACACACACACACACACACA\x00"))},
			wantName: "FRED",
		},
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotName, _ := decodeNBNSName(tt.args.buffer); gotName != tt.wantName {
				t.Errorf("decodeNBNSName() = %v, want %v", gotName, tt.wantName)
			}
		})
	}
}
