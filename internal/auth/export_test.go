package auth

// These hooks let external integration tests inspect Auth credentials and SMS capacity.
var (
	NewTokenForTest    = newToken
	HexDigestForTest   = hexDigest
	TokenDigestForTest = tokenDigest
)

func (s *Server) SaturateSMSForTest() func() {
	added := cap(s.smsSlots) - len(s.smsSlots)
	for range added {
		s.smsSlots <- struct{}{}
	}
	return func() {
		for range added {
			<-s.smsSlots
		}
	}
}
