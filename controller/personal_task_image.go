package controller

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	pluginruntime "github.com/QuantumNous/new-api/pkg/jsplugin"
	"github.com/QuantumNous/new-api/relay"
	relaychannel "github.com/QuantumNous/new-api/relay/channel"
	pluginadaptor "github.com/QuantumNous/new-api/relay/channel/task/jsplugin"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func personalTaskImagePlugin(task *model.Task) *pluginruntime.LoadedPlugin {
	if task.OrganizationID != 0 || task.Status != model.TaskStatusSuccess || !task.ResultRetrievable() ||
		!taskHasPluginExecution(task) || task.PrivateData.UpstreamTaskID == "" {
		return nil
	}
	snapshot := task.PrivateData.Execution.TaskPlugin
	if snapshot.Key != "alibaba" {
		return nil
	}
	// The first supported producer is the direct asynchronous DashScope
	// poller. Its retained output carries the provider's terminal status.
	var retained struct {
		Output struct {
			Status string `json:"task_status"`
			TaskID string `json:"task_id"`
		} `json:"output"`
	}
	if common.Unmarshal(task.Data, &retained) != nil || retained.Output.Status != "SUCCEEDED" ||
		retained.Output.TaskID != task.PrivateData.UpstreamTaskID {
		return nil
	}
	registry := pluginruntime.DefaultRegistry
	plugin, ok := relay.ResolveTaskPluginForPlatform(registry.Generation(), task.Platform)
	if !ok || plugin.Meta.Key != snapshot.Key || plugin.Meta.Version != snapshot.Version ||
		!registry.IsFactoryPlugin(plugin) {
		return nil
	}
	return plugin
}

func PinPersonalTaskImage(c *gin.Context) {
	identity, rowID, ok := personalMediaRequest(c)
	if !ok {
		return
	}
	if c.Param("artifact_key") != model.PersonalTaskImageKey {
		writePersonalMediaError(c, gorm.ErrRecordNotFound)
		return
	}
	ctx := c.Request.Context()
	existing, err := model.ReadPersonalTaskImage(ctx, identity, rowID)
	if err == nil {
		c.JSON(http.StatusOK, existing)
		return
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		writePersonalMediaError(c, err)
		return
	}
	task, err := model.ReadPersonalTaskArtifact(ctx, identity, rowID)
	if err != nil {
		writePersonalMediaError(c, err)
		return
	}

	plugin := personalTaskImagePlugin(task)
	if plugin == nil {
		writePersonalMediaError(c, gorm.ErrRecordNotFound)
		return
	}
	adaptor := pluginadaptor.New(plugin)
	artifacts, err := adaptor.ListArtifacts(task)
	if err != nil || len(artifacts) == 0 || artifacts[0].Key != model.PersonalTaskImageKey || artifacts[0].Type != "image" {
		writePersonalMediaError(c, gorm.ErrRecordNotFound)
		return
	}
	if _, err = configureTaskArtifactAdaptor(task, adaptor); err != nil {
		writeTaskArtifactProjectionError(c, err)
		return
	}
	descriptor, err := adaptor.BuildContentRequest(ctx, task, model.PersonalTaskImageKey,
		relaychannel.TaskArtifactClientRequest{Method: http.MethodGet})
	if err != nil || descriptor == nil || !descriptor.Credentialless || descriptor.Method != http.MethodGet || len(descriptor.ContentPath) != 0 {
		writeTaskArtifactError(c, http.StatusBadGateway, "artifact_upstream_error", "Failed to fetch complete image")
		return
	}
	data, mimeType, err := capturePersonalImage(c, task.ChannelId, task.TaskID, descriptor, model.PersonalTaskImageMaxBytes)
	if err != nil {
		writeTaskArtifactError(c, http.StatusBadGateway, "artifact_upstream_error", "Failed to fetch complete image")
		return
	}
	stored, created, err := model.PinPersonalTaskImage(ctx, identity, task, data, mimeType)
	switch {
	case errors.Is(err, model.ErrPersonalTaskImageBudget):
		writeTaskArtifactError(c, http.StatusRequestEntityTooLarge, "artifact_storage_limit", "Personal media storage budget exceeded")
	case errors.Is(err, model.ErrPersonalTaskImageChanged):
		writeTaskArtifactError(c, http.StatusConflict, "artifact_changed", "Task image changed while it was being pinned")
	case err != nil:
		writePersonalMediaError(c, err)
	case created:
		c.JSON(http.StatusCreated, stored)
	default:
		c.JSON(http.StatusOK, stored)
	}
}

func PersonalTaskImageVersion(c *gin.Context) {
	identity, rowID, ok := personalMediaRequest(c)
	if !ok {
		return
	}
	if c.Param("artifact_key") != model.PersonalTaskImageKey || c.Param("version") != strconv.Itoa(model.PersonalTaskImageVersion) {
		writePersonalMediaError(c, gorm.ErrRecordNotFound)
		return
	}
	stored, err := model.ReadPersonalTaskImage(c.Request.Context(), identity, rowID)
	if err != nil {
		writePersonalMediaError(c, err)
		return
	}
	c.Header("Content-Type", stored.MIME)
	c.Header("Content-Length", strconv.FormatInt(stored.Length, 10))
	c.Header("ETag", strconv.Quote(stored.Digest))
	c.Status(http.StatusOK)
	if c.Request.Method != http.MethodHead {
		_, _ = c.Writer.Write(stored.Data)
	}
}
