package dedup

import (
	"reflect"
	"testing"
)

type payload struct {
	Value string
	Note  string
}

func TestByKey(t *testing.T) {
	tests := []struct {
		name string
		in   []payload
		want []payload
	}{
		{
			name: "nil input",
			in:   nil,
			want: []payload{},
		},
		{
			name: "no duplicates preserves order",
			in:   []payload{{Value: "a"}, {Value: "b"}, {Value: "c"}},
			want: []payload{{Value: "a"}, {Value: "b"}, {Value: "c"}},
		},
		{
			name: "duplicates keep first occurrence",
			in:   []payload{{Value: "a", Note: "first"}, {Value: "b"}, {Value: "a", Note: "second"}},
			want: []payload{{Value: "a", Note: "first"}, {Value: "b"}},
		},
		{
			name: "all duplicates collapse to one",
			in:   []payload{{Value: "x"}, {Value: "x"}, {Value: "x"}},
			want: []payload{{Value: "x"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ByKey(tt.in, func(p payload) string { return p.Value })
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ByKey() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
