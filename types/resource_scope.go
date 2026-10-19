package types

// ResourceScope identifies a resource owner, independently of the actor's
// credentials or platform role. Only personal scopes are supported for now.
// It is an internal value, not a request DTO or an authorization grant.
type ResourceScope struct {
	userID int
}

func NewPersonalResourceScope(userID int) (ResourceScope, bool) {
	if userID <= 0 {
		return ResourceScope{}, false
	}
	return ResourceScope{userID: userID}, true
}

// PersonalOwnerID rejects the zero value; no scope represents all users.
func (s ResourceScope) PersonalOwnerID() (int, bool) {
	return s.userID, s.userID > 0
}

// OrganizationID is always zero until organization authorization is supported.
func (s ResourceScope) OrganizationID() int {
	return 0
}
