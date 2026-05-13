package common

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
)

// Stage 9: WebSocket Binary Fallback.
//
// Wraps WireGuard packets inside a WebSocket binary frame to allow
// tunneling over WebSocket transports (TCP/TLS, HTTP/2 CONNECT, etc.).
// This is the final fallback when both raw UDP and QUIC are blocked.
//
// Frame structure (RFC 6455 §5.2):
//
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-------+-+-------------+-------------------------------+
//  |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
//  |I|S|S|S|  (4)  |A|     (7)     |   (if payload len==126/127)   |
//  |N|V|V|V|       |S|             |                               |
//  | |1|2|3|       |K|             |                               |
//  +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
//  |   Masking key (4 bytes, client-to-server only)                 |
//  + - - - - - - - - - - - - - - - +-------------------------------+
//  |   Payload (masked)                                            |
//  +---------------------------------------------------------------+
//
// This implementation always produces **client-to-server** masked frames
// (bitmask 0x80 set). Masking key is random per frame.

var ErrNotWebSocketFrame = errors.New("not a valid WebSocket OE frame")

// WrapWebSocket frames data as a WebSocket binary message (opcode 0x02),
// client-to-server with random masking.
func WrapWebSocket(data []byte) ([]byte, error) {
	// Masking key (4 random bytes).
	maskKey := make([]byte, 4)
	if _, err := rand.Read(maskKey); err != nil {
		return nil, err
	}

	// Determine payload length encoding.
	payLen := len(data)
	var headerLen int

	if payLen <= 125 {
		headerLen = 2 + 4 // 2 base + 4 mask
	} else if payLen <= 65535 {
		headerLen = 4 + 4 // 2 base + 2 ext + 4 mask
	} else {
		return nil, errors.New("payload too large for WebSocket frame (>65535)")
	}

	total := headerLen + payLen
	buf := make([]byte, total)

	pos := 0
	// FIN=1, RSV=0, opcode=2 (binary)
	buf[pos] = 0x82
	pos++

	// Mask=1, payload len
	if payLen <= 125 {
		buf[pos] = 0x80 | byte(payLen)
		pos++
	} else {
		buf[pos] = 0x80 | 126
		pos++
		binary.BigEndian.PutUint16(buf[pos:], uint16(payLen))
		pos += 2
	}

	// Mask key.
	copy(buf[pos:], maskKey)
	pos += 4

	// Payload with mask.
	for i := 0; i < payLen; i++ {
		buf[pos+i] = data[i] ^ maskKey[i%4]
	}

	return buf, nil
}

// UnwrapWebSocket extracts the payload from a WebSocket binary frame.
// Expects FIN=1, opcode=2, mask=1 (client-to-server).
// Zero allocations — mutates input in-place to demask, returns sub-slice.
func UnwrapWebSocket(data []byte) ([]byte, error) {
	if len(data) < 2+4 { // minimum: 2 header + 4 mask
		return nil, ErrNotWebSocketFrame
	}

	pos := 0

	// First byte: FIN(1)=1, RSV(3)=0, opcode(4)=2
	if data[pos] != 0x82 {
		return nil, ErrNotWebSocketFrame
	}
	pos++

	// Second byte: mask(1)=1, payload len(7)
	masked := data[pos] & 0x80
	if masked == 0 {
		return nil, ErrNotWebSocketFrame // server-to-server frames should not appear
	}

	payLen := int(data[pos] & 0x7F)
	pos++

	if payLen == 126 {
		if pos+2 > len(data) {
			return nil, ErrNotWebSocketFrame
		}
		payLen = int(binary.BigEndian.Uint16(data[pos:]))
		pos += 2
	} else if payLen == 127 {
		// 64-bit length not supported in this simplified implementation.
		return nil, ErrNotWebSocketFrame
	}

	// Mask key.
	if pos+4 > len(data) {
		return nil, ErrNotWebSocketFrame
	}
	maskKey := data[pos : pos+4]
	pos += 4

	// Payload.
	if pos+payLen > len(data) {
		return nil, ErrNotWebSocketFrame
	}

	// Demask in-place, return sub-slice.
	payload := data[pos : pos+payLen]
	for i := range payload {
		payload[i] ^= maskKey[i%4]
	}

	return payload, nil
}
