package common

import "crypto/rand"

// Pad adds random padding to reach targetSize.
func Pad(data []byte, targetSize int) ([]byte, error) {
	if len(data) >= targetSize {
		return data, nil
	}
	padding := make([]byte, targetSize-len(data))
	if _, err := rand.Read(padding); err != nil {
		return nil, err
	}
	return append(data, padding...), nil
}

// TrimPad removes padding added by Pad.
func TrimPad(data []byte, originalLen int) []byte {
	if len(data) <= originalLen {
		return data
	}
	return data[:originalLen]
}
