package common

import (
	"bytes"
	"testing"
)

// mockClock returns a fixed timestamp and allows tests to manipulate time.
func setMockClock(ts int64) {
	currentTimestamp = func() int64 { return ts }
}

func restoreClock() {
	currentTimestamp = defaultClock
}

func TestGenerateProbeCookie_Basic(t *testing.T) {
	restoreClock()

	key := makeTestKey()
	ts := int64(1700000000)

	cookie, err := GenerateProbeCookie(key, ts)
	if err != nil {
		t.Fatalf("GenerateProbeCookie: %v", err)
	}
	if len(cookie) != ProbeCookieLen {
		t.Errorf("cookie len = %d, want %d", len(cookie), ProbeCookieLen)
	}

	// Determinism.
	cookie2, _ := GenerateProbeCookie(key, ts)
	if !bytes.Equal(cookie, cookie2) {
		t.Errorf("GenerateProbeCookie is not deterministic")
	}

	// Different timestamp → different cookie.
	cookie3, _ := GenerateProbeCookie(key, ts+1)
	if bytes.Equal(cookie, cookie3) {
		t.Errorf("different timestamps produced same cookie")
	}
}

func TestGenerateProbeCookie_InvalidKey(t *testing.T) {
	_, err := GenerateProbeCookie(make([]byte, 16), 0)
	if err == nil {
		t.Errorf("expected error for invalid key")
	}
}

func TestMarkProbeCookie_RoundTrip(t *testing.T) {
	key := makeTestKey()
	ts := int64(1700000000)
	setMockClock(ts)
	defer restoreClock()

	sid, err := MarkProbeCookie(key)
	if err != nil {
		t.Fatalf("MarkProbeCookie: %v", err)
	}
	if len(sid) != 32 {
		t.Errorf("sessionID len = %d, want 32", len(sid))
	}

	// Extract should find the timestamp.
	extractedTS, ok := extractProbeCookieTimestamp(sid, key, DefaultTimeWindow)
	if !ok {
		t.Errorf("extractProbeCookieTimestamp failed")
	}
	if extractedTS != ts {
		t.Errorf("extracted TS = %d, want %d", extractedTS, ts)
	}
}

func TestExtractProbeCookie_TimeWindow(t *testing.T) {
	key := makeTestKey()
	now := int64(1700000000)
	window := int64(10)

	// Generate cookie at 'now'.
	expectedCookie, _ := GenerateProbeCookie(key, now)
	sid := make([]byte, 32)
	copy(sid[:ProbeCookieLen], expectedCookie)

	// Clock at 'now' — should find.
	setMockClock(now)
	_, ok := extractProbeCookieTimestamp(sid, key, window)
	if !ok {
		t.Errorf("should find cookie at now")
	}

	// Clock at 'now + window' — edge, should find.
	setMockClock(now + window)
	_, ok = extractProbeCookieTimestamp(sid, key, window)
	if !ok {
		t.Errorf("should find cookie at now+%d", window)
	}

	// Clock at 'now - window' — edge, should find.
	setMockClock(now - window)
	_, ok = extractProbeCookieTimestamp(sid, key, window)
	if !ok {
		t.Errorf("should find cookie at now-%d", window)
	}

	// Clock at 'now + window + 1' — outside, should NOT find.
	setMockClock(now + window + 1)
	_, ok = extractProbeCookieTimestamp(sid, key, window)
	if ok {
		t.Errorf("should NOT find cookie at now+%d", window+1)
	}

	// Clock at 'now - window - 1' — outside, should NOT find.
	setMockClock(now - window - 1)
	_, ok = extractProbeCookieTimestamp(sid, key, window)
	if ok {
		t.Errorf("should NOT find cookie at now-%d", window+1)
	}

	restoreClock()
}

func TestIsProbePacket(t *testing.T) {
	key := makeTestKey()
	now := int64(1700000000)
	setMockClock(now)
	defer restoreClock()

	// Build a handshake embedding a valid probe cookie in session ID.
	sid, _ := MarkProbeCookie(key)
	original := makeHandshakeData(148)

	// Obfuscate with a custom session ID (simplified: use BalancedMode wrapper,
	// then overwrite session ID portion).
	wrapped, _ := ObfuscateClientHello(original, "cloudflare.com")

	// Find and replace session ID in the wrapped packet.
	// Session ID is at offset: 5(record) + 4(handshake) + 2(version) + 32(random) = 43.
	// But wait — ObfuscateClientHello already sets a random session ID.
	// We need to patch it with our probe-cookie-carrying session ID.

	patched := make([]byte, len(wrapped))
	copy(patched, wrapped)

	// Parse to find session ID position.
	pos := 5 + 4 + 2 + 32 // after record+handshake+version+random
	if pos < len(patched) {
		origSessLen := int(patched[pos])
		// We write a 32-byte session ID with probe cookie.
		patched[pos] = 32
		// Extend/replace session ID bytes.
		// This is hacky — easier: build from scratch with known positions.
		_ = origSessLen
	}

	// Simpler approach: build a valid ClientHello manually with known session ID.
	validWithCookie := buildClientHelloWithSessionID(original, sid)

	// Test 1: valid packet with correct cookie → not a probe.
	if IsProbePacket(validWithCookie, key, DefaultTimeWindow) {
		t.Errorf("valid packet with cookie should NOT be a probe")
	}

	// Test 2: nil packet → probe.
	if !IsProbePacket(nil, key, DefaultTimeWindow) {
		t.Errorf("nil packet should be a probe")
	}

	// Test 3: empty packet → probe.
	if !IsProbePacket([]byte{}, key, DefaultTimeWindow) {
		t.Errorf("empty packet should be a probe")
	}

	// Test 4: valid packet with wrong key → probe.
	wrongKey := make([]byte, 32)
	wrongKey[0] = 0xFF
	if !IsProbePacket(validWithCookie, wrongKey, DefaultTimeWindow) {
		t.Errorf("packet with wrong key should be a probe")
	}

	// Test 5: packet with session ID < 8 bytes → probe.
	shortSidPacket := buildClientHelloWithSessionID(original, []byte{0x01, 0x02})
	if !IsProbePacket(shortSidPacket, key, DefaultTimeWindow) {
		t.Errorf("packet with short session ID should be a probe")
	}

	// Test 6: expired cookie → probe.
	setMockClock(now + DefaultTimeWindow + 100)
	if !IsProbePacket(validWithCookie, key, DefaultTimeWindow) {
		t.Errorf("packet with expired cookie should be a probe")
	}

	setMockClock(now)
}

func TestIsProbePacket_Truncated(t *testing.T) {
	key := makeTestKey()
	now := int64(1700000000)
	setMockClock(now)
	defer restoreClock()

	// Various truncated packets should be classified as probes.
	truncated := [][]byte{
		{0x16},
		{0x16, 0x03, 0x03},
		{0x16, 0x03, 0x03, 0x00, 0x00},
		make([]byte, 10),
		make([]byte, 50),
	}

	for i, pkt := range truncated {
		t.Run(itoa(i), func(t *testing.T) {
			if !IsProbePacket(pkt, key, DefaultTimeWindow) {
				t.Errorf("truncated packet should be a probe")
			}
		})
	}
}

// --- Helpers ---

// buildClientHelloWithSessionID creates a minimal TLS ClientHello with a
// specific session ID, wrapping the given data in a GREASE extension.
func buildClientHelloWithSessionID(data, sessionID []byte) []byte {
	// Use ObfuscateClientHello as base, then rebuild with custom session ID.
	// Simpler: construct manually.

	greasePayloadLen := 2 + len(data) // magic + data
	greaseExt := make([]byte, 4+greasePayloadLen)
	greaseExt[0] = 0xFA
	greaseExt[1] = 0xFA
	greaseExt[2] = byte(greasePayloadLen >> 8)
	greaseExt[3] = byte(greasePayloadLen)
	greaseExt[4] = tlsMagic0
	greaseExt[5] = tlsMagic1
	copy(greaseExt[6:], data)

	// SNI ext
	sni := "cloudflare.com"
	sniExtLen := 2 + 2 + 1 + 2 + len(sni)
	sniExt := make([]byte, 4+sniExtLen)
	sniExt[0] = 0x00
	sniExt[1] = 0x00
	sniExt[2] = byte(sniExtLen >> 8)
	sniExt[3] = byte(sniExtLen)
	sniExt[4] = byte(len(sni) + 3 >> 8)
	sniExt[5] = byte(len(sni) + 3)
	sniExt[6] = 0x00
	sniExt[7] = byte(len(sni) >> 8)
	sniExt[8] = byte(len(sni))
	copy(sniExt[9:], sni)

	extensions := append(sniExt, greaseExt...)

	// Cipher suites
	cs := []byte{0x00, 0x02, 0x00, 0x2F}
	comp := []byte{0x01, 0x00}
	clientRandom := make([]byte, 32)

	beforeExt := 5 + 4 + 2 + 32 + 1 + len(sessionID) + len(cs) + len(comp)
	totalLen := beforeExt + 2 + len(extensions)

	buf := make([]byte, totalLen)
	pos := 0

	buf[pos] = 0x16
	pos++
	buf[pos] = 0x03
	buf[pos+1] = 0x03
	pos += 2
	buf[pos] = byte((totalLen - 5) >> 8)
	buf[pos+1] = byte(totalLen - 5)
	pos += 2

	buf[pos] = 0x01
	pos++
	buf[pos] = byte((totalLen - 9) >> 16)
	buf[pos+1] = byte((totalLen - 9) >> 8)
	buf[pos+2] = byte(totalLen - 9)
	pos += 3

	buf[pos] = 0x03
	buf[pos+1] = 0x03
	pos += 2

	copy(buf[pos:], clientRandom)
	pos += 32

	buf[pos] = byte(len(sessionID))
	pos++
	copy(buf[pos:], sessionID)
	pos += len(sessionID)

	copy(buf[pos:], cs)
	pos += len(cs)

	copy(buf[pos:], comp)
	pos += len(comp)

	buf[pos] = byte(len(extensions) >> 8)
	buf[pos+1] = byte(len(extensions))
	pos += 2
	copy(buf[pos:], extensions)

	return buf
}
