package cli

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseEnumeration(t *testing.T) {
	tests := []struct {
		spec    string
		want    Enumeration
		wantErr string
	}{
		{spec: DefaultEnumeration, want: Enumeration{
			Plugins: ItemsVulnerable, Themes: ItemsVulnerable,
			ConfigBackups: true, DBExports: true, BackupFolders: true, Users: &DefaultUserIDs,
		}},
		{spec: "", want: Enumeration{}},
		{spec: "none", want: Enumeration{}},
		{spec: " ap , T ,", want: Enumeration{Plugins: ItemsAll, Themes: ItemsPopular}},
		{spec: "p,at", want: Enumeration{Plugins: ItemsPopular, Themes: ItemsAll}},
		{spec: "u5-20", want: Enumeration{Users: &IDRange{From: 5, To: 20}}},
		{spec: "u7", want: Enumeration{Users: &IDRange{From: 7, To: 7}}},
		{spec: "cb,cb", want: Enumeration{ConfigBackups: true}},
		{spec: "vp,ap", wantErr: "mutually exclusive"},
		{spec: "t,vt", wantErr: "mutually exclusive"},
		{spec: "u0-3", wantErr: "invalid ID range"},
		{spec: "u9-3", wantErr: "invalid ID range"},
		{spec: "ux", wantErr: "invalid ID range"},
		{spec: "u1-", wantErr: "invalid ID range"},
		{spec: "m", wantErr: "not supported yet"},
		{spec: "tt", wantErr: "not supported yet"},
		{spec: "bogus", wantErr: "unknown choice"},
	}
	for _, tt := range tests {
		t.Run(tt.spec, func(t *testing.T) {
			got, err := ParseEnumeration(tt.spec)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want one containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}
