package service

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"nodectl/internal/database"

	"gorm.io/gorm"
)

type TrafficLandingNode struct {
	UUID      string `json:"uuid"`
	InstallID string `json:"install_id"`
	Name      string `json:"name"`
	Region    string `json:"region"`
}

type TrafficConsumptionItem struct {
	UUID            string `json:"uuid"`
	InstallID       string `json:"install_id"`
	Name            string `json:"name"`
	Region          string `json:"region"`
	TrafficUp       int64  `json:"traffic_up"`
	TrafficDown     int64  `json:"traffic_down"`
	TotalBytes      int64  `json:"total_bytes"`
	UploadRatio     string `json:"upload_ratio"`
	TrafficUpdateAt string `json:"traffic_update_at"`
}

type TrafficConsumptionRank struct {
	GeneratedAt string                   `json:"generated_at"`
	TotalUp     int64                    `json:"total_up"`
	TotalDown   int64                    `json:"total_down"`
	TotalBytes  int64                    `json:"total_bytes"`
	Items       []TrafficConsumptionItem `json:"items"`
}

type TrafficSeriesOptions struct {
	NodeUUID      string
	Hours         int
	IntervalHours int
	Mode          string // total | increment
	Date          string // YYYY-MM-DD
}

type TrafficSeriesPoint struct {
	Time       string `json:"time"`
	Label      string `json:"label"`
	UpBytes    int64  `json:"up_bytes"`
	DownBytes  int64  `json:"down_bytes"`
	TotalBytes int64  `json:"total_bytes"`
}

type TrafficSeriesResult struct {
	NodeUUID      string               `json:"node_uuid"`
	NodeName      string               `json:"node_name"`
	Mode          string               `json:"mode"`
	Hours         int                  `json:"hours"`
	IntervalHours int                  `json:"interval_hours"`
	GeneratedAt   string               `json:"generated_at"`
	Points        []TrafficSeriesPoint `json:"points"`
}

type hourlyAgg struct {
	Has      bool
	LastAt   time.Time
	LastUp   int64
	LastDown int64
	SumUp    int64
	SumDown  int64
}

func hourKey(t time.Time) int {
	return t.Year()*1000000 + int(t.Month())*10000 + t.Day()*100 + t.Hour()
}

func twoHourKey(t time.Time) int {
	h := t.Hour()
	h = (h / 2) * 2
	return t.Year()*1000000 + int(t.Month())*10000 + t.Day()*100 + h
}

func dayKey(t time.Time) int {
	return t.Year()*10000 + int(t.Month())*100 + t.Day()
}

func normalizeTrafficMode(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "increment" {
		return "increment"
	}
	return "total"
}

func normalizeTrafficHours(v int) int {
	if v <= 0 {
		return 24
	}
	if v > 24*14 {
		return 24 * 14
	}
	return v
}

func normalizeTrafficIntervalHours(v int) int {
	if v == 2 {
		return 2
	}
	return 1
}

func normalizeTrafficRetentionDays(v int) int {
	if v < 1 {
		return 30
	}
	if v > 3650 {
		return 3650
	}
	return v
}

func loadTrafficRetentionDays(tx *gorm.DB) int {
	var cfg database.SysConfig
	if err := tx.Where("key = ?", "pref_traffic_stats_retention_days").First(&cfg).Error; err != nil {
		return 30
	}
	days, err := strconv.Atoi(strings.TrimSpace(cfg.Value))
	if err != nil {
		return 30
	}
	return normalizeTrafficRetentionDays(days)
}

func cleanupExpiredTrafficStats(tx *gorm.DB, now time.Time, retentionDays int) error {
	cutoff := now.AddDate(0, 0, -normalizeTrafficRetentionDays(retentionDays))
	cutoffDayKey := dayKey(cutoff)
	return tx.Where("day_key < ?", cutoffDayKey).Delete(&database.NodeTrafficStat{}).Error
}

// SaveNodeTrafficReport 在节点上报流量时同时更新 node_pool 和历史统计表。
func SaveNodeTrafficReport(installID string, rxBytes, txBytes int64, reportedAt time.Time) (bool, error) {
	installID = strings.TrimSpace(installID)
	if installID == "" {
		return false, nil
	}
	if reportedAt.IsZero() {
		reportedAt = time.Now()
	}

	found := false
	err := database.DB.Transaction(func(tx *gorm.DB) error {
		var node database.NodePool
		if err := tx.Where("install_id = ?", installID).First(&node).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return nil
			}
			return err
		}
		found = true

		if err := tx.Model(&database.NodePool{}).
			Where("uuid = ?", node.UUID).
			Updates(map[string]interface{}{
				"traffic_down":      rxBytes,
				"traffic_up":        txBytes,
				"traffic_update_at": reportedAt,
				"updated_at":        time.Now(),
			}).Error; err != nil {
			return err
		}

		rec := database.NodeTrafficStat{
			NodeUUID:   node.UUID,
			InstallID:  node.InstallID,
			ReportedAt: reportedAt,
			HourKey:    hourKey(reportedAt),
			TwoHourKey: twoHourKey(reportedAt),
			DayKey:     dayKey(reportedAt),
			TXBytes:    txBytes,
			RXBytes:    rxBytes,
		}
		if err := tx.Create(&rec).Error; err != nil {
			return err
		}

		retentionDays := loadTrafficRetentionDays(tx)
		if err := cleanupExpiredTrafficStats(tx, reportedAt, retentionDays); err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return false, err
	}

	return found, nil
}

// GetTrafficLandingNodes 返回可用于统计的落地节点列表。
func GetTrafficLandingNodes() ([]TrafficLandingNode, error) {
	var nodes []database.NodePool
	if err := database.DB.
		Where("routing_type = ?", 2).
		Order("sort_index ASC, updated_at DESC").
		Find(&nodes).Error; err != nil {
		return nil, err
	}

	result := make([]TrafficLandingNode, 0, len(nodes))
	for _, n := range nodes {
		result = append(result, TrafficLandingNode{
			UUID:      n.UUID,
			InstallID: n.InstallID,
			Name:      n.Name,
			Region:    strings.ToUpper(strings.TrimSpace(n.Region)),
		})
	}
	return result, nil
}

func parseTrafficRankDate(raw string) (time.Time, bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false, nil
	}
	t, err := time.ParseInLocation("2006-01-02", raw, time.Local)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("日期格式错误，需为 YYYY-MM-DD")
	}
	return t, true, nil
}

// GetTrafficConsumptionRank 返回节点流量消耗排行榜（支持按日期查询历史）。
func GetTrafficConsumptionRank(limit int, rankDate string) (*TrafficConsumptionRank, error) {
	if limit <= 0 {
		limit = 30
	}
	if limit > 200 {
		limit = 200
	}

	selectedDate, hasDate, err := parseTrafficRankDate(rankDate)
	if err != nil {
		return nil, err
	}

	var nodes []database.NodePool
	if err := database.DB.
		Select("uuid", "install_id", "name", "region", "traffic_up", "traffic_down", "traffic_update_at", "updated_at").
		Where("install_id <> ?", "").
		Order("updated_at DESC").
		Find(&nodes).Error; err != nil {
		return nil, err
	}

	if !hasDate {
		sort.SliceStable(nodes, func(i, j int) bool {
			totalI := nodes[i].TrafficUp + nodes[i].TrafficDown
			totalJ := nodes[j].TrafficUp + nodes[j].TrafficDown
			if totalI == totalJ {
				return nodes[i].UpdatedAt.After(nodes[j].UpdatedAt)
			}
			return totalI > totalJ
		})

		if len(nodes) > limit {
			nodes = nodes[:limit]
		}

		items := make([]TrafficConsumptionItem, 0, len(nodes))
		var totalUp int64
		var totalDown int64

		for _, n := range nodes {
			total := n.TrafficUp + n.TrafficDown
			totalUp += n.TrafficUp
			totalDown += n.TrafficDown

			ratio := "0.00"
			if n.TrafficUp > 0 {
				ratio = fmt.Sprintf("%.2f", float64(n.TrafficDown)/float64(n.TrafficUp))
			}

			updateAt := "--"
			if n.TrafficUpdateAt != nil {
				updateAt = n.TrafficUpdateAt.Format("2006-01-02 15:04")
			}

			items = append(items, TrafficConsumptionItem{
				UUID:            n.UUID,
				InstallID:       n.InstallID,
				Name:            n.Name,
				Region:          strings.ToUpper(strings.TrimSpace(n.Region)),
				TrafficUp:       n.TrafficUp,
				TrafficDown:     n.TrafficDown,
				TotalBytes:      total,
				UploadRatio:     ratio,
				TrafficUpdateAt: updateAt,
			})
		}

		return &TrafficConsumptionRank{
			GeneratedAt: time.Now().Format("2006-01-02"),
			TotalUp:     totalUp,
			TotalDown:   totalDown,
			TotalBytes:  totalUp + totalDown,
			Items:       items,
		}, nil
	}

	dayStart := selectedDate
	dayEnd := selectedDate.AddDate(0, 0, 1)

	uuidToNode := make(map[string]database.NodePool, len(nodes))
	for _, n := range nodes {
		uuidToNode[n.UUID] = n
	}

	var samples []database.NodeTrafficStat
	if err := database.DB.
		Select("node_uuid", "reported_at", "tx_bytes", "rx_bytes").
		Where("reported_at >= ? AND reported_at < ?", dayStart, dayEnd).
		Order("node_uuid ASC, reported_at ASC").
		Find(&samples).Error; err != nil {
		return nil, err
	}

	type trafficPair struct {
		up   int64
		down int64
	}

	prevRaw := make(map[string]trafficPair, len(nodes))
	baseline := make(map[string]trafficPair, len(nodes))
	upByNode := make(map[string]int64, len(nodes))
	downByNode := make(map[string]int64, len(nodes))
	lastAtByNode := make(map[string]time.Time, len(nodes))

	seenNode := make(map[string]struct{}, len(samples))
	for _, s := range samples {
		if _, ok := seenNode[s.NodeUUID]; ok {
			continue
		}
		seenNode[s.NodeUUID] = struct{}{}

		var b database.NodeTrafficStat
		res := database.DB.
			Select("tx_bytes", "rx_bytes").
			Where("node_uuid = ? AND reported_at < ?", s.NodeUUID, dayStart).
			Order("reported_at DESC").
			Limit(1).
			Find(&b)
		if res.Error != nil {
			return nil, res.Error
		}
		if res.RowsAffected > 0 {
			baseline[s.NodeUUID] = trafficPair{up: b.TXBytes, down: b.RXBytes}
		}
	}

	for _, s := range samples {
		currUp := s.TXBytes
		currDown := s.RXBytes

		base, hasBase := baseline[s.NodeUUID]
		prev, hasPrev := prevRaw[s.NodeUUID]

		deltaUp := currUp
		deltaDown := currDown
		if hasPrev {
			deltaUp = currUp - prev.up
			deltaDown = currDown - prev.down
		} else if hasBase {
			deltaUp = currUp - base.up
			deltaDown = currDown - base.down
		}

		if deltaUp < 0 {
			deltaUp = currUp
		}
		if deltaDown < 0 {
			deltaDown = currDown
		}

		upByNode[s.NodeUUID] += deltaUp
		downByNode[s.NodeUUID] += deltaDown
		prevRaw[s.NodeUUID] = trafficPair{up: currUp, down: currDown}

		if lastAtByNode[s.NodeUUID].IsZero() || s.ReportedAt.After(lastAtByNode[s.NodeUUID]) {
			lastAtByNode[s.NodeUUID] = s.ReportedAt
		}
	}

	items := make([]TrafficConsumptionItem, 0, len(nodes))
	for _, n := range nodes {
		up := upByNode[n.UUID]
		down := downByNode[n.UUID]
		total := up + down

		ratio := "0.00"
		if up > 0 {
			ratio = fmt.Sprintf("%.2f", float64(down)/float64(up))
		}

		updateAt := "--"
		if t, ok := lastAtByNode[n.UUID]; ok && !t.IsZero() {
			updateAt = t.Format("2006-01-02 15:04")
		}

		items = append(items, TrafficConsumptionItem{
			UUID:            n.UUID,
			InstallID:       n.InstallID,
			Name:            n.Name,
			Region:          strings.ToUpper(strings.TrimSpace(n.Region)),
			TrafficUp:       up,
			TrafficDown:     down,
			TotalBytes:      total,
			UploadRatio:     ratio,
			TrafficUpdateAt: updateAt,
		})
	}

	sort.SliceStable(items, func(i, j int) bool {
		if items[i].TotalBytes == items[j].TotalBytes {
			if items[i].TrafficUpdateAt == items[j].TrafficUpdateAt {
				return items[i].Name < items[j].Name
			}
			return items[i].TrafficUpdateAt > items[j].TrafficUpdateAt
		}
		return items[i].TotalBytes > items[j].TotalBytes
	})

	if len(items) > limit {
		items = items[:limit]
	}

	var totalUp int64
	var totalDown int64
	for _, item := range items {
		totalUp += item.TrafficUp
		totalDown += item.TrafficDown
	}

	return &TrafficConsumptionRank{
		GeneratedAt: dayStart.Format("2006-01-02"),
		TotalUp:     totalUp,
		TotalDown:   totalDown,
		TotalBytes:  totalUp + totalDown,
		Items:       items,
	}, nil
}

// QueryTrafficSeries 查询节点流量时序统计（支持总量/增量，支持 1h/2h 粒度）。
func QueryTrafficSeries(opts TrafficSeriesOptions) (*TrafficSeriesResult, error) {
	nodeUUID := strings.TrimSpace(opts.NodeUUID)
	if nodeUUID == "" {
		return nil, fmt.Errorf("node_uuid 不能为空")
	}

	hours := normalizeTrafficHours(opts.Hours)
	intervalHours := normalizeTrafficIntervalHours(opts.IntervalHours)
	mode := normalizeTrafficMode(opts.Mode)
	selectedDate, hasDate, err := parseTrafficRankDate(opts.Date)
	if err != nil {
		return nil, err
	}

	var node database.NodePool
	if err := database.DB.Select("uuid", "name").Where("uuid = ?", nodeUUID).First(&node).Error; err != nil {
		return nil, err
	}

	now := time.Now()
	endHour := now.Truncate(time.Hour)
	startHour := endHour.Add(-time.Duration(hours-1) * time.Hour)
	if hasDate {
		hours = 24
		startHour = selectedDate
		endHour = selectedDate.Add(23 * time.Hour)
	}

	var samples []database.NodeTrafficStat
	if err := database.DB.
		Where("node_uuid = ? AND hour_key >= ? AND hour_key <= ?", nodeUUID, hourKey(startHour), hourKey(endHour)).
		Order("reported_at ASC").
		Find(&samples).Error; err != nil {
		return nil, err
	}

	var baseline database.NodeTrafficStat
	baselineUp := int64(0)
	baselineDown := int64(0)
	hasBaseline := false
	baselineRes := database.DB.
		Where("node_uuid = ? AND reported_at < ?", nodeUUID, startHour).
		Order("reported_at DESC").
		Limit(1).
		Find(&baseline)
	if baselineRes.Error != nil {
		return nil, baselineRes.Error
	}
	if baselineRes.RowsAffected > 0 {
		hasBaseline = true
		baselineUp = baseline.TXBytes
		baselineDown = baseline.RXBytes
	}

	aggByHour := make(map[time.Time]hourlyAgg, hours+2)
	prevUp := baselineUp
	prevDown := baselineDown
	hasPrev := hasBaseline

	for _, s := range samples {
		h := s.ReportedAt.Truncate(time.Hour)
		agg := aggByHour[h]
		agg.Has = true

		upDelta := s.TXBytes
		downDelta := s.RXBytes
		if hasPrev {
			upDelta = s.TXBytes - prevUp
			downDelta = s.RXBytes - prevDown
			if upDelta < 0 {
				upDelta = s.TXBytes
			}
			if downDelta < 0 {
				downDelta = s.RXBytes
			}
		}
		agg.SumUp += upDelta
		agg.SumDown += downDelta

		if agg.LastAt.IsZero() || s.ReportedAt.After(agg.LastAt) {
			agg.LastAt = s.ReportedAt
			agg.LastUp = s.TXBytes
			agg.LastDown = s.RXBytes
		}
		aggByHour[h] = agg

		prevUp = s.TXBytes
		prevDown = s.RXBytes
		hasPrev = true
	}

	points := make([]TrafficSeriesPoint, 0, hours)
	runningUp := baselineUp
	runningDown := baselineDown

	for ts := startHour; !ts.After(endHour); ts = ts.Add(time.Duration(intervalHours) * time.Hour) {
		intervalEnd := ts.Add(time.Duration(intervalHours) * time.Hour)

		bucketUp := int64(0)
		bucketDown := int64(0)
		bucketLatestAt := time.Time{}
		bucketHasTotal := false

		for h := ts; h.Before(intervalEnd); h = h.Add(time.Hour) {
			agg, ok := aggByHour[h]
			if !ok || !agg.Has {
				continue
			}
			if mode == "increment" {
				bucketUp += agg.SumUp
				bucketDown += agg.SumDown
				continue
			}

			if !bucketHasTotal || agg.LastAt.After(bucketLatestAt) {
				bucketLatestAt = agg.LastAt
				bucketUp = agg.LastUp
				bucketDown = agg.LastDown
				bucketHasTotal = true
			}
		}

		if mode == "total" {
			if bucketHasTotal {
				runningUp = bucketUp
				runningDown = bucketDown
			} else {
				bucketUp = runningUp
				bucketDown = runningDown
			}
		}

		label := ts.Format("01-02 15:04")
		if intervalHours == 2 {
			label = fmt.Sprintf("%s~%s", ts.Format("15:00"), ts.Add(time.Hour).Format("15:00"))
		}

		points = append(points, TrafficSeriesPoint{
			Time:       ts.Format(time.RFC3339),
			Label:      label,
			UpBytes:    bucketUp,
			DownBytes:  bucketDown,
			TotalBytes: bucketUp + bucketDown,
		})
	}

	return &TrafficSeriesResult{
		NodeUUID:      node.UUID,
		NodeName:      node.Name,
		Mode:          mode,
		Hours:         hours,
		IntervalHours: intervalHours,
		GeneratedAt:   now.Format(time.RFC3339),
		Points:        points,
	}, nil
}
