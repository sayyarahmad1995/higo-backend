package auth

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// AccessProof holds the digest of a syntactically valid access token.
// It makes no claim about the existence or state of a session.
type AccessProof struct {
	digest []byte
}

// NewAccessProof derives a proof from an access token. Invalid tokens produce
// the zero value so callers can preserve when they report unauthorized.
func NewAccessProof(bearer string) AccessProof {
	return AccessProof{digest: tokenDigest(bearer, "at_")}
}

// Validate checks token format only.
func (p AccessProof) Validate() error {
	if p.digest == nil {
		return unauthorized
	}
	return nil
}

// LockAccount resolves an active session and locks its account and session,
// in that order, inside the caller's transaction.
func (p AccessProof) LockAccount(ctx context.Context, tx pgx.Tx) (int64, error) {
	if err := p.Validate(); err != nil {
		return 0, err
	}
	return lockSessionAccount(ctx, tx, p.digest)
}

// ResolveAccount checks the live session for request admission. Callers must
// use LockAccount in their own transaction before accessing account-owned data.
func (s *Server) ResolveAccount(ctx context.Context, proof AccessProof) (int64, error) {
	user, err := s.accountForProof(ctx, proof)
	return user.ID, err
}
