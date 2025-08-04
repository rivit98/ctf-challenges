package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChunkize(t *testing.T) {
	tests := map[string]struct {
		input string
	}{
		"empty message": {
			input: "",
		},
		"non-empty message (short)": {
			input: "A",
		},
		"non-empty message (short 2)": {
			input: "AB",
		},
		"non-empty message (long)": {
			input: "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
		},
	}

	for tname, tc := range tests {
		t.Run(tname, func(t *testing.T) {
			transport := Transport{}

			err := transport.EnqueuePackets([]byte(tc.input))
			require.NoError(t, err)

			packets := transport.sendQ

			assert.Greater(t, len(packets), 2)
			packets = packets[1 : len(packets)-1]

			decoded, err := decodeMessage(packets)
			require.NoError(t, err)

			assert.Equal(t, tc.input, decoded)
		})
	}
}
