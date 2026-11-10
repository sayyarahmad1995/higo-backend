package auth

// These hooks keep the HTTP integration tests in an external package while
// preserving their assertions on stored credentials, evidence and SMS capacity.
var (
	RequiredOnboardingDocumentsForTest = requiredOnboardingDocuments
	NewTokenForTest                    = newToken
	HexDigestForTest                   = hexDigest
	TokenDigestForTest                 = tokenDigest
)

const (
	PurgeAbandonedOnboardingDocumentsForTest = purgeAbandonedOnboardingDocuments
	MaxDriverImageForTest                    = maxDriverImage
	MaxVehicleDocumentForTest                = maxVehicleDocument
)

func (s *Server) OpenDocumentForTest(encrypted []byte, id int64, version int, kind string) ([]byte, error) {
	return s.driverDocumentCipher.Open(nil, nil, encrypted, onboardingDocumentAAD(id, version, kind))
}

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
