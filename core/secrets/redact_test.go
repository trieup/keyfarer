package secrets

import "testing"

func TestRedactSecrets(t *testing.T) {
	tests := []struct {
		name   string
		out    string
		values []string
		want   string
	}{
		{
			name:   "masks every occurrence",
			out:    "token=tok-value-42 again tok-value-42",
			values: []string{"tok-value-42"},
			want:   "token=[REDACTED] again [REDACTED]",
		},
		{
			name:   "longest first so overlaps mask fully",
			out:    "prefix-secret-suffix",
			values: []string{"secret", "prefix-secret-suffix"},
			want:   "[REDACTED]",
		},
		{
			name:   "skips empty and short values",
			out:    "keep 1 ab abcd here",
			values: []string{"", "1", "ab", "abcd"},
			want:   "keep 1 ab abcd here",
		},
		{
			name:   "redacts value at threshold length",
			out:    "value=abcde done",
			values: []string{"abcde"},
			want:   "value=[REDACTED] done",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := redactSecrets(tc.out, tc.values); got != tc.want {
				t.Fatalf("redactSecrets() = %q, want %q", got, tc.want)
			}
		})
	}
}
