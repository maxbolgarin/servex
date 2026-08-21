package servex

import (
	"testing"
)

// TestSQLBoolScan pins the dialect differences that broke Postgres logins:
// Postgres/MySQL BOOLEAN columns arrive as a real bool, SQLite INTEGER columns
// arrive as int64, and some drivers hand back text.
func TestSQLBoolScan(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		src     any
		want    bool
		wantErr bool
	}{
		{name: "postgres true", src: true, want: true},
		{name: "postgres false", src: false, want: false},
		{name: "sqlite one", src: int64(1), want: true},
		{name: "sqlite zero", src: int64(0), want: false},
		{name: "null is false", src: nil, want: false},
		{name: "float one", src: float64(1), want: true},
		{name: "text t", src: "t", want: true},
		{name: "text false", src: "false", want: false},
		{name: "bytes true", src: []byte("true"), want: true},
		{name: "bytes zero", src: []byte("0"), want: false},
		{name: "empty string is false", src: "", want: false},
		{name: "unparsable text errors", src: "maybe", wantErr: true},
		{name: "unsupported type errors", src: struct{}{}, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got sqlBool
			err := got.Scan(tc.src)

			if tc.wantErr {
				if err == nil {
					t.Fatalf("Scan(%#v): expected an error, got none", tc.src)
				}
				return
			}
			if err != nil {
				t.Fatalf("Scan(%#v): unexpected error: %v", tc.src, err)
			}
			if bool(got) != tc.want {
				t.Fatalf("Scan(%#v) = %v, want %v", tc.src, bool(got), tc.want)
			}
		})
	}
}
