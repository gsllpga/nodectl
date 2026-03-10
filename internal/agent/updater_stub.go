// 路径: internal/agent/updater_stub.go
//go:build !linux

package agent

import "context"

// Updater 非 Linux 平台的空实现桩
type Updater struct{}

// NewUpdater 非 Linux 返回空实例（无操作）
func NewUpdater() (*Updater, error) { return &Updater{}, nil }

// RecordStartup 非 Linux 不进行崩溃循环检测
func (u *Updater) RecordStartup() bool { return false }

// MarkHealthy 非 Linux 空操作
func (u *Updater) MarkHealthy() {}

// Run 非 Linux 空操作（立即返回）
func (u *Updater) Run(ctx context.Context) {}

// TriggerCheck 非 Linux 不支持更新检查
func (u *Updater) TriggerCheck(ctx context.Context) error { return nil }
