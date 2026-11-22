package model

import (
	"bytes"
	"image"
	"image/png"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPreparedLegacyMedia(t *testing.T) {
	dialects := []string{"sqlite"}
	if os.Getenv("NEWAPI_REQUIRE_DATABASES") == "1" {
		dialects = []string{"sqlite", "mysql", "postgres"}
	} else if dialect := os.Getenv("TEST_ORGANIZATION_DIALECT"); dialect != "" {
		dialects = []string{dialect}
	}
	for _, dialect := range dialects {
		t.Run(dialect, func(t *testing.T) {
			f := organizationDatabase(t, dialect)
			tables := []any{&Midjourney{}, &Task{}, &MidjourneyImageVersion{}, &PersonalTaskImage{},
				&LegacyMediaSnapshot{}, &LegacyMediaSnapshotEntry{}, &LegacyMediaRouteObservation{}, &LegacyMediaRevocation{}}
			for _, table := range tables {
				require.False(t, DB.Migrator().HasTable(table), "fixture must own every migrated table")
			}
			require.NoError(t, DB.AutoMigrate(tables...))
			t.Cleanup(func() {
				for _, table := range tables {
					assert.NoError(t, DB.Migrator().DropTable(table))
				}
			})
			owner, other, administrator := f.identities[0], f.identities[1], f.identities[6]
			ctx := t.Context()
			var data bytes.Buffer
			require.NoError(t, png.Encode(&data, image.NewRGBA(image.Rect(0, 0, 1, 1))))
			mj := Midjourney{MjId: "GatewayImageA", UserId: owner.UserID, SubmitTime: 1919,
				Status: "SUCCESS", Progress: "100%", ImageUrl: "https://fixture.invalid/image.png"}
			require.NoError(t, DB.Create(&mj).Error)
			mjBytes, created, err := PinPersonalMidjourneyImage(ctx, owner, &mj, data.Bytes(), "image/png")
			require.NoError(t, err)
			require.True(t, created)
			task := Task{TaskID: "FrozenImageA", UserId: owner.UserID, SubmitTime: 1920, Status: TaskStatusSuccess,
				Platform:    "alibaba",
				PrivateData: TaskPrivateData{Execution: &TaskExecutionSnapshot{TaskPlugin: &TaskPluginSnapshot{Key: "alibaba", Version: "1.0.0"}}}}
			require.NoError(t, DB.Create(&task).Error)
			taskBytes, created, err := PinPersonalTaskImage(ctx, owner, &task, data.Bytes(), "image/png")
			require.NoError(t, err)
			require.True(t, created)
			mjBinding := LegacyMediaBinding{
				LegacyMediaSubject: LegacyMediaSubject{
					LegacyMediaRoute: LegacyMediaRoute{Family: LegacyMidjourneyImage, PublicID: mj.MjId, ArtifactKey: "image"},
					RowID:            int64(mj.Id), OwnerID: owner.UserID, SubmitTime: mj.SubmitTime,
				},
				VersionID: mjBytes.ID, Version: mjBytes.Version, ContentDigest: mjBytes.Digest,
				ContentLength: mjBytes.Length, EvidenceDigest: strings.Repeat("a", 64),
			}
			taskBinding := LegacyMediaBinding{
				LegacyMediaSubject: LegacyMediaSubject{
					LegacyMediaRoute: LegacyMediaRoute{Family: LegacyTaskArtifactV1, PublicID: task.TaskID, ArtifactKey: PersonalTaskImageKey},
					RowID:            task.ID, OwnerID: owner.UserID, SubmitTime: task.SubmitTime,
				},
				VersionID: taskBytes.ID, Version: taskBytes.Version, ContentDigest: taskBytes.Digest,
				ContentLength: taskBytes.Length, EvidenceDigest: strings.Repeat("b", 64),
			}

			// An unresolved entry aborts the entire batch, including a valid entry.
			wrong := taskBinding
			wrong.ContentDigest = strings.Repeat("c", 64)
			_, err = PrepareLegacyMediaSnapshot(ctx, []LegacyMediaBinding{mjBinding, wrong})
			require.ErrorIs(t, err, ErrLegacyMediaUnproven)
			var count int64
			require.NoError(t, DB.Model(&LegacyMediaSnapshotEntry{}).Count(&count).Error)
			assert.Zero(t, count)

			type preparation struct {
				id  string
				err error
			}
			result := make(chan preparation, 2)
			for _, members := range [][]LegacyMediaBinding{{mjBinding, taskBinding}, {taskBinding, mjBinding}} {
				go func() {
					id, err := PrepareLegacyMediaSnapshot(ctx, members)
					result <- preparation{id, err}
				}()
			}
			first, second := <-result, <-result
			require.NoError(t, first.err)
			require.NoError(t, second.err)
			require.NotEmpty(t, first.id)
			require.Equal(t, first.id, second.id)
			require.NoError(t, DB.Model(&LegacyMediaSnapshotEntry{}).Count(&count).Error)
			assert.EqualValues(t, 2, count)

			id, mjRoute, taskRoute := first.id, mjBinding.LegacyMediaRoute, taskBinding.LegacyMediaRoute
			got, err := ReadPreparedLegacyMedia(ctx, id, taskRoute)
			require.NoError(t, err)
			assert.Equal(t, taskBinding, *got)
			alternate := taskRoute
			alternate.ArtifactKey = "image-2"
			_, err = ReadPreparedLegacyMedia(ctx, id, alternate)
			assert.ErrorIs(t, err, ErrLegacyMediaUnproven)

			// The second global identity is unpinned. A version join alone would miss it.
			collision := Midjourney{MjId: mj.MjId, UserId: other.UserID, SubmitTime: 1921}
			if dialect == "mysql" {
				collision.MjId = strings.ToLower(mj.MjId)
			}
			require.NoError(t, DB.Create(&collision).Error)
			_, err = ReadPreparedLegacyMedia(ctx, id, mjRoute)
			assert.ErrorIs(t, err, ErrLegacyMediaUnproven)
			require.NoError(t, DB.Delete(&collision).Error)
			require.NoError(t, DB.Model(&task).Update("organization_id", 23).Error)
			_, err = ReadPreparedLegacyMedia(ctx, id, taskRoute)
			assert.ErrorIs(t, err, ErrLegacyMediaUnproven)
			require.NoError(t, DB.Model(&task).Update("organization_id", 0).Error)
			require.NoError(t, DB.Model(&task).Update("submit_time", 1922).Error)
			_, err = ReadPreparedLegacyMedia(ctx, id, taskRoute)
			assert.ErrorIs(t, err, ErrLegacyMediaUnproven)
			require.NoError(t, DB.Model(&task).Update("submit_time", taskBinding.SubmitTime).Error)

			assert.ErrorIs(t, RevokePreparedLegacyMedia(ctx, other, id, mjRoute), ErrLegacyMediaUnproven)
			assert.ErrorIs(t, RevokePreparedLegacyMedia(ctx, administrator, id, mjRoute), ErrLegacyMediaUnproven)
			require.NoError(t, DB.Model(&UserSession{}).Where("sid = ?", owner.SessionID).Update("revoked_at", time.Now().Unix()).Error)
			assert.ErrorIs(t, RevokePreparedLegacyMedia(ctx, owner, id, mjRoute), ErrUserSessionInactive)
			require.NoError(t, DB.Model(&UserSession{}).Where("sid = ?", owner.SessionID).Update("revoked_at", 0).Error)
			// An owner can revoke an already known object while its source is absent.
			require.NoError(t, DB.Model(&mj).Update("image_url", "").Error)
			require.NoError(t, RevokePreparedLegacyMedia(ctx, owner, id, mjRoute))
			require.NoError(t, DB.Model(&mj).Update("image_url", "https://fixture.invalid/image.png").Error)
			require.NoError(t, RevokePreparedLegacyMedia(ctx, owner, id, mjRoute))
			require.NoError(t, DB.Model(&LegacyMediaRevocation{}).Count(&count).Error)
			assert.EqualValues(t, 1, count)

			updated := mjBinding
			updated.EvidenceDigest = strings.Repeat("d", 64)
			newID, err := PrepareLegacyMediaSnapshot(ctx, []LegacyMediaBinding{updated})
			require.NoError(t, err)
			require.NotEqual(t, id, newID)
			for _, snapshot := range []string{id, newID} {
				_, err = ReadPreparedLegacyMedia(ctx, snapshot, mjRoute)
				assert.ErrorIs(t, err, ErrLegacyMediaRevoked)
			}
			// The same route once belonged to MJ's original row. Replacing it with
			// a new personal owner and valid version must not admit that address.
			require.NoError(t, DB.Model(&mj).Update("mj_id", "renamed-original").Error)
			reused := Midjourney{MjId: mjRoute.PublicID, UserId: other.UserID, SubmitTime: 2001,
				Status: "SUCCESS", Progress: "100%", ImageUrl: "https://fixture.invalid/replacement.png"}
			if dialect == "mysql" {
				reused.MjId = strings.ToLower(reused.MjId)
			}
			require.NoError(t, DB.Create(&reused).Error)
			replacement, created, err := PinPersonalMidjourneyImage(ctx, other, &reused, data.Bytes(), "image/png")
			require.NoError(t, err)
			require.True(t, created)
			newBinding := mjBinding
			newBinding.PublicID, newBinding.OwnerID, newBinding.RowID, newBinding.SubmitTime =
				reused.MjId, reused.UserId, int64(reused.Id), reused.SubmitTime
			newBinding.VersionID = replacement.ID
			_, err = PrepareLegacyMediaSnapshot(ctx, []LegacyMediaBinding{newBinding})
			require.ErrorIs(t, err, ErrLegacyMediaUnproven)
			require.NoError(t, DB.Delete(&reused).Error)
			require.NoError(t, DB.Model(&mj).Update("mj_id", mjRoute.PublicID).Error)
			// Restoring the old row does not undo observed reuse of the address.
			_, err = ReadPreparedLegacyMedia(ctx, id, mjRoute)
			require.ErrorIs(t, err, ErrLegacyMediaUnproven)
			require.NoError(t, DB.Model(&LegacyMediaSnapshot{}).Count(&count).Error)
			assert.EqualValues(t, 2, count)

			_, err = ReadPreparedLegacyMedia(ctx, id, taskRoute)
			require.NoError(t, err)
			if dialect == "mysql" {
				var charset, original string
				require.NoError(t, DB.Raw(`SELECT character_set_name, collation_name FROM information_schema.columns
					WHERE table_schema = DATABASE() AND table_name = 'legacy_media_route_observations' AND column_name = 'public_id'`).
					Row().Scan(&charset, &original))
				// The isolated schema can inherit different defaults from its server.
				require.Regexp(t, "^[a-zA-Z0-9_]+$", charset)
				require.Regexp(t, "^[a-zA-Z0-9_]+$", original)
				different := "utf8mb4_bin"
				if different == original {
					different = "utf8mb4_unicode_ci"
				}
				const alter = "ALTER TABLE legacy_media_route_observations MODIFY COLUMN public_id VARCHAR(191) CHARACTER SET "
				require.NoError(t, DB.Exec(alter+"utf8mb4 COLLATE "+different+" NOT NULL").Error)
				unmatched := taskBinding
				unmatched.EvidenceDigest = strings.Repeat("e", 64)
				_, err = PrepareLegacyMediaSnapshot(ctx, []LegacyMediaBinding{unmatched})
				assert.ErrorIs(t, err, ErrLegacyMediaUnproven)
				_, err = ReadPreparedLegacyMedia(ctx, id, taskRoute)
				assert.ErrorIs(t, err, ErrLegacyMediaUnproven)
				require.NoError(t, DB.Exec(alter+charset+" COLLATE "+original+" NOT NULL").Error)
				_, err = ReadPreparedLegacyMedia(ctx, id, taskRoute)
				require.NoError(t, err)
			}
			require.NoError(t, DB.Model(&PersonalTaskImage{}).Where("id = ?", taskBytes.ID).Update("data", []byte("corrupt")).Error)
			_, err = ReadPreparedLegacyMedia(ctx, id, taskRoute)
			assert.ErrorIs(t, err, ErrLegacyMediaUnproven)
		})
	}
}
