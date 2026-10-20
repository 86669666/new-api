package service

import (
	"strconv"

	"github.com/QuantumNous/new-api/model"
)

type OrganizationCapabilities struct {
	OrganizationRead       bool `json:"organization_read"`
	MembersRead            bool `json:"members_read"`
	EventsRead             bool `json:"events_read"`
	ResourceAccess         bool `json:"resource_access"`
	OrganizationTokenIssue bool `json:"organization_token_issue"`
	OrganizationSpend      bool `json:"organization_spend"`
	OrganizationMutation   bool `json:"organization_mutation"`
}

type OrganizationAccess struct {
	OrgID            string                   `json:"org_id"`
	Name             string                   `json:"name"`
	Revision         string                   `json:"revision"`
	MyRole           string                   `json:"my_role"`
	MyMemberRevision string                   `json:"my_member_revision"`
	Capabilities     OrganizationCapabilities `json:"capabilities"`
}

type OrganizationRequestContext struct {
	ActorUserID  string              `json:"actor_user_id"`
	OrgID        string              `json:"org_id"`
	ScopeKind    string              `json:"scope_kind"`
	Organization *OrganizationAccess `json:"organization"`
}

type OrganizationAccessMember struct {
	MemberID string `json:"member_id"`
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	Revision string `json:"revision"`
	JoinedAt int64  `json:"joined_at"`
}

type OrganizationAccessEvent struct {
	EventID              string `json:"event_id"`
	OrgID                string `json:"org_id"`
	OrganizationRevision string `json:"organization_revision"`
	ActorUserID          string `json:"actor_user_id"`
	Action               string `json:"action"`
	SubjectUserID        string `json:"subject_user_id"`
	ObjectKind           string `json:"object_kind"`
	ObjectID             string `json:"object_id"`
	ObjectGeneration     string `json:"object_generation"`
	BeforeState          string `json:"before_state"`
	AfterState           string `json:"after_state"`
	ReasonCode           string `json:"reason_code"`
	Role                 string `json:"role"`
	ExpiresAt            int64  `json:"expires_at"`
	CreatedAt            int64  `json:"created_at"`
}

type OrganizationAccessPage[T any] struct {
	Items       []T     `json:"items"`
	Limit       int     `json:"limit"`
	NextAfterID *string `json:"next_after_id"`
}

func organizationAccessView(v model.OrganizationView) OrganizationAccess {
	governance := v.MyRole == model.OrganizationRoleOwner || v.MyRole == model.OrganizationRoleAdmin
	// ReadOrganizationAccess supplies only active membership views. These flags
	// describe existing governance eligibility and task reads, never a grant.
	return OrganizationAccess{OrgID: strconv.FormatInt(v.ID, 10), Name: v.Name, Revision: strconv.FormatInt(v.Revision, 10), MyRole: v.MyRole, MyMemberRevision: strconv.FormatInt(v.MyMemberRevision, 10), Capabilities: OrganizationCapabilities{
		OrganizationRead: true, MembersRead: true, EventsRead: governance,
		ResourceAccess: true, OrganizationMutation: governance,
	}}
}

// OrganizationAccessResponse constructs the complete allowlisted wire shape.
// None of these advisory projections is an authorization credential.
func OrganizationAccessResponse(identity AuthIdentity, kind model.OrganizationAccessKind, orgID int64, page model.OrganizationPage) (any, int, error) {
	result, err := model.ReadOrganizationAccess(identity, kind, orgID, page)
	if err != nil {
		return nil, result.ActorRole, err
	}
	switch kind {
	case model.OrganizationAccessDiscovery:
		out := OrganizationAccessPage[OrganizationAccess]{Items: make([]OrganizationAccess, 0, len(result.Organizations)), Limit: page.Limit}
		for _, v := range result.Organizations {
			out.Items = append(out.Items, organizationAccessView(v))
		}
		if len(out.Items) == page.Limit {
			out.NextAfterID = &out.Items[len(out.Items)-1].OrgID
		}
		return out, result.ActorRole, nil
	case model.OrganizationAccessContext:
		out := OrganizationRequestContext{ActorUserID: strconv.Itoa(identity.UserID), OrgID: strconv.FormatInt(orgID, 10), ScopeKind: "personal"}
		if result.Organization != nil {
			v := organizationAccessView(*result.Organization)
			out.Organization = &v
			out.ScopeKind = "organization"
		}
		return out, result.ActorRole, nil
	case model.OrganizationAccessDetail:
		return organizationAccessView(*result.Organization), result.ActorRole, nil
	case model.OrganizationAccessMembers:
		out := OrganizationAccessPage[OrganizationAccessMember]{Items: make([]OrganizationAccessMember, 0, len(result.Members)), Limit: page.Limit}
		for _, v := range result.Members {
			out.Items = append(out.Items, OrganizationAccessMember{MemberID: strconv.FormatInt(v.ID, 10), UserID: strconv.Itoa(v.UserID), Username: v.Username, Role: v.Role, Revision: strconv.FormatInt(v.Revision, 10), JoinedAt: v.JoinedAt})
		}
		if len(out.Items) == page.Limit {
			out.NextAfterID = &out.Items[len(out.Items)-1].MemberID
		}
		return out, result.ActorRole, nil
	case model.OrganizationAccessEvents:
		out := OrganizationAccessPage[OrganizationAccessEvent]{Items: make([]OrganizationAccessEvent, 0, len(result.Events)), Limit: page.Limit}
		for _, v := range result.Events {
			out.Items = append(out.Items, OrganizationAccessEvent{EventID: strconv.FormatInt(v.ID, 10), OrgID: strconv.FormatInt(v.OrganizationID, 10), OrganizationRevision: strconv.FormatInt(v.OrganizationRevision, 10), ActorUserID: strconv.Itoa(v.ActorUserID), Action: v.Action, SubjectUserID: strconv.Itoa(v.SubjectUserID), ObjectKind: v.ObjectKind, ObjectID: strconv.FormatInt(v.ObjectID, 10), ObjectGeneration: strconv.FormatInt(v.ObjectGeneration, 10), BeforeState: v.BeforeState, AfterState: v.AfterState, ReasonCode: v.ReasonCode, Role: v.Role, ExpiresAt: v.ExpiresAt, CreatedAt: v.CreatedAt})
		}
		if len(out.Items) == page.Limit {
			out.NextAfterID = &out.Items[len(out.Items)-1].EventID
		}
		return out, result.ActorRole, nil
	}
	return nil, 0, model.ErrOrganizationInvalidInput
}
