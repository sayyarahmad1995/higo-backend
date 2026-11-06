package auth

import (
	"testing"
	"time"
)

func TestOnboardingAgeAndValidity(t *testing.T) {
	today := time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)
	draft := map[string]string{"legal_name": "Test Driver", "date_of_birth": "2008-11-07", "cnic_number": "1234567890123"}
	if !completeDriver(draft, today) {
		t.Fatal("18th birthday must qualify")
	}
	draft["date_of_birth"] = "2008-11-08"
	if completeDriver(draft, today) {
		t.Fatal("underage applicant qualified")
	}
	draft["cnic_validity"], draft["license_expiry"], draft["registration_validity"] = "lifetime", "2026-11-07", "no_expiry"
	if !completeEvidence(draft, requiredOnboardingDocuments, today) {
		t.Fatal("explicit valid declarations rejected")
	}
	draft["cnic_validity"] = ""
	if completeEvidence(draft, requiredOnboardingDocuments, today) {
		t.Fatal("missing date inferred as lifetime")
	}
	draft["cnic_validity"], draft["cnic_expiry"] = "expires", "2026-11-06"
	if completeEvidence(draft, requiredOnboardingDocuments, today) {
		t.Fatal("expired CNIC accepted")
	}
	draft["cnic_expiry"] = "2026-11-07"
	if completeEvidence(draft, requiredOnboardingDocuments[:len(requiredOnboardingDocuments)-1], today) {
		t.Fatal("missing photo accepted")
	}
	withAdditional := append(append([]string{}, requiredOnboardingDocuments...), "additional")
	if completeEvidence(draft, withAdditional, today) {
		t.Fatal("missing additional validity accepted")
	}
	draft["additional_validity"] = "no_expiry"
	if !completeEvidence(draft, withAdditional, today) {
		t.Fatal("optional declaration rejected")
	}
}
