package nbns

import "testing"

func Test_encodeNetBiosName(t *testing.T) {
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
			if got := encodeNetBiosName(tt.args.name); got != tt.want {
				t.Errorf("encodeNetBiosName() =|%x|%v, want |%x|%v", got, len(got), tt.want, len(tt.want))
			}
		})
	}
}
