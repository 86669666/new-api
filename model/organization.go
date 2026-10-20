package model

import (
	"errors"
	"math"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/QuantumNous/new-api/common"
	"gorm.io/gorm"
)

const (
	OrganizationRoleOwner         = "owner"
	OrganizationRoleAdmin         = "admin"
	OrganizationRoleMember        = "member"
	OrganizationPending           = "pending"
	OrganizationAccepted          = "accepted"
	OrganizationDeclined          = "declined"
	OrganizationRevoked           = "revoked"
	OrganizationCancelled         = "cancelled"
	OrganizationExpired           = "expired"
	OrganizationMembershipMessage = "Leave all organizations before deleting this account. Owners must transfer ownership or dissolve their organizations first."
)

var (
	ErrOrganizationInvalidInput     = errors.New("invalid organization command")
	ErrOrganizationUnauthenticated  = errors.New("organization session is inactive")
	ErrOrganizationNotFound         = errors.New("organization object not found")
	ErrOrganizationForbidden        = errors.New("organization operation is forbidden")
	ErrOrganizationDisabled         = errors.New("organization is disabled")
	ErrOrganizationConflict         = errors.New("organization state changed")
	ErrOrganizationAlreadyMember    = errors.New("user is already an organization member")
	ErrOrganizationInvitationExists = errors.New("organization invitation already exists")
	ErrOrganizationExpired          = errors.New("organization request expired")
	ErrOrganizationTerminal         = errors.New("organization request is already resolved")
	ErrOrganizationMembershipActive = common.NewMessage(OrganizationMembershipMessage)
)

type Organization struct {
	ID                     int64  `gorm:"primaryKey"`
	Name                   string `gorm:"type:varchar(64);not null"`
	CreatedByUserID        int    `gorm:"not null"`
	OwnerUserID            int    `gorm:"not null;index:idx_org_owner_state,priority:1"`
	Revision               int64  `gorm:"not null"`
	OwnershipVersion       int64  `gorm:"not null"`
	SelfDisabledAt         int64  `gorm:"not null"`
	SelfDisabledReason     string `gorm:"type:varchar(128);not null"`
	PlatformDisabledAt     int64  `gorm:"not null"`
	PlatformDisabledReason string `gorm:"type:varchar(128);not null"`
	DissolvedAt            int64  `gorm:"not null;index:idx_org_owner_state,priority:2"`
	CreatedAt              int64  `gorm:"not null;autoCreateTime:false"`
	UpdatedAt              int64  `gorm:"not null;autoUpdateTime:false"`
}

type OrganizationMember struct {
	ID             int64  `gorm:"primaryKey"`
	OrganizationID int64  `gorm:"not null;uniqueIndex:uq_org_member,priority:1;index:idx_org_member_user,priority:3"`
	UserID         int    `gorm:"not null;uniqueIndex:uq_org_member,priority:2;index:idx_org_member_user,priority:1"`
	Role           string `gorm:"type:varchar(16);not null"`
	Revision       int64  `gorm:"not null"`
	JoinedAt       int64  `gorm:"not null"`
	RemovedAt      int64  `gorm:"not null;index:idx_org_member_user,priority:2"`
	UpdatedAt      int64  `gorm:"not null;autoUpdateTime:false"`
	RemovalReason  string `gorm:"type:varchar(32);not null"`
}

type OrganizationInvitation struct {
	ID                    int64  `gorm:"primaryKey"`
	OrganizationID        int64  `gorm:"not null;uniqueIndex:uq_org_invitee,priority:1"`
	TargetUserID          int    `gorm:"not null;uniqueIndex:uq_org_invitee,priority:2;index:idx_org_invitee_inbox,priority:1"`
	InviterUserID         int    `gorm:"not null"`
	InviterMemberRevision int64  `gorm:"not null"`
	Role                  string `gorm:"type:varchar(16);not null"`
	Generation            int64  `gorm:"not null"`
	Status                string `gorm:"type:varchar(16);not null;index:idx_org_invitee_inbox,priority:2"`
	ExpiresAt             int64  `gorm:"not null;index:idx_org_invitee_inbox,priority:3"`
	ResolvedAt            int64  `gorm:"not null"`
	CreatedAt             int64  `gorm:"not null;autoCreateTime:false"`
	UpdatedAt             int64  `gorm:"not null;autoUpdateTime:false"`
	ResolutionReason      string `gorm:"type:varchar(32);not null"`
}

type OrganizationOwnershipTransfer struct {
	ID                 int64  `gorm:"primaryKey"`
	OrganizationID     int64  `gorm:"not null;uniqueIndex:uq_org_transfer"`
	FromUserID         int    `gorm:"not null"`
	ToUserID           int    `gorm:"not null;index:idx_org_transfer_inbox,priority:1"`
	Generation         int64  `gorm:"not null"`
	OwnerVersion       int64  `gorm:"not null"`
	FromMemberRevision int64  `gorm:"not null"`
	ToMemberRevision   int64  `gorm:"not null"`
	Status             string `gorm:"type:varchar(16);not null;index:idx_org_transfer_inbox,priority:2"`
	ExpiresAt          int64  `gorm:"not null;index:idx_org_transfer_inbox,priority:3"`
	ResolvedAt         int64  `gorm:"not null"`
	CreatedAt          int64  `gorm:"not null;autoCreateTime:false"`
	UpdatedAt          int64  `gorm:"not null;autoUpdateTime:false"`
	ResolutionReason   string `gorm:"type:varchar(32);not null"`
}

type OrganizationEvent struct {
	ID                   int64  `gorm:"primaryKey;index:idx_org_event_order,priority:2"`
	OrganizationID       int64  `gorm:"not null;index:idx_org_event_order,priority:1"`
	OrganizationRevision int64  `gorm:"not null"`
	ActorUserID          int    `gorm:"not null"`
	Action               string `gorm:"type:varchar(48);not null"`
	SubjectUserID        int    `gorm:"not null"`
	ObjectKind           string `gorm:"type:varchar(24);not null"`
	ObjectID             int64  `gorm:"not null"`
	ObjectGeneration     int64  `gorm:"not null"`
	BeforeState          string `gorm:"type:varchar(32);not null"`
	AfterState           string `gorm:"type:varchar(32);not null"`
	ReasonCode           string `gorm:"type:varchar(32);not null"`
	Role                 string `gorm:"type:varchar(16);not null"`
	ExpiresAt            int64  `gorm:"not null"`
	CreatedAt            int64  `gorm:"not null;autoCreateTime:false"`
}

// OrganizationCommand is an internal domain command, never an HTTP request DTO.
// Each entry point rejects fields unrelated to its action. Versions are mandatory.
type OrganizationCommand struct {
	OrganizationID   int64
	Revision         int64
	TargetUserID     int
	Name             string
	Username         string
	ExpectedUsername string // Internal exact selector binding; never part of the proof JSON.
	Role             string
	Disabled         bool
	Reason           string
	ObjectID         int64
	Generation       int64
	Replace          bool
	Authorization    *OrganizationAuthorization
}

func organizationName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if !utf8.ValidString(name) || utf8.RuneCountInString(name) < 1 || utf8.RuneCountInString(name) > 64 {
		return "", ErrOrganizationInvalidInput
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", ErrOrganizationInvalidInput
		}
	}
	return name, nil
}

func organizationNextVersion(v int64) (int64, error) {
	if v < 1 || v == math.MaxInt64 {
		return 0, ErrOrganizationConflict
	}
	return v + 1, nil
}

func organizationCAS(result *gorm.DB) error {
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return ErrOrganizationConflict
	}
	return nil
}

// The user row lock is shared with organization joins/ownership changes. This
// must precede auth-version fencing: that external cache effect cannot roll back.
func guardOrganizationUserDeletion(tx *gorm.DB, userID int) error {
	var user User
	if err := lockForUpdate(tx.Unscoped()).First(&user, userID).Error; err != nil {
		return err
	}
	var members []OrganizationMember
	if err := lockForUpdate(tx.Model(&OrganizationMember{})).Joins("JOIN organizations ON organizations.id = organization_members.organization_id").Where("organization_members.user_id = ? AND organization_members.removed_at = 0 AND organizations.dissolved_at = 0", userID).Find(&members).Error; err != nil {
		return err
	}
	if len(members) > 0 {
		return ErrOrganizationMembershipActive
	}
	return nil
}
