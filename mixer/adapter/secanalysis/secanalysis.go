//go:generate $GOPATH/src/istio.io/istio/bin/mixer_codegen.sh -f mixer/adapter/secanalysis/config/config.proto

// Package secanalysis is a proof of concept adapter for collecting security information for
// later evaluation and analysis
package secanalysis

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"cloud.google.com/go/bigquery"
	"istio.io/istio/mixer/adapter/secanalysis/config"
	"istio.io/istio/mixer/pkg/adapter"
	"istio.io/istio/mixer/template/metric"
)

type (
	builder struct {
		adpCfg      *config.Params
		metricTypes map[string]*metric.Type
	}
	handler struct {
		client      *bigquery.Client
		dataset     string
		table       string
		metricTypes map[string]*metric.Type
		env         adapter.Env
	}
)

// ensure types implement the requisite interfaces
var _ metric.HandlerBuilder = &builder{}
var _ metric.Handler = &handler{}

///////////////// Configuration-time Methods ///////////////

// adapter.HandlerBuilder#Build
func (b *builder) Build(ctx context.Context, env adapter.Env) (adapter.Handler, error) {
	var client *bigquery.Client
	if len(b.adpCfg.Project) > 0 {
		var err error
		client, err = bigquery.NewClient(ctx, b.adpCfg.Project)
		if err != nil {
			str := fmt.Sprintf("%v", err)
			env.Logger().Warningf("Failed to create bigquery client: %s %v", str, 124)
			return nil, err
		}
	}
	return &handler{client: client, dataset: b.adpCfg.Dataset, table: b.adpCfg.Table, metricTypes: b.metricTypes, env: env}, nil
}

// adapter.HandlerBuilder#SetAdapterConfig
func (b *builder) SetAdapterConfig(cfg adapter.Config) {
	b.adpCfg = cfg.(*config.Params)
}

// adapter.HandlerBuilder#Validate
func (b *builder) Validate() (ce *adapter.ConfigErrors) {
	if len(b.adpCfg.Project) > 0 {
		if len(b.adpCfg.Dataset) == 0 {
			ce = ce.Append("Failed cfg validation", errors.New("Empty Dataset"))
		}
		if len(b.adpCfg.Table) == 0 {
			ce = ce.Append("Failed cfg validation", errors.New("Empty Table"))
		}
	}
	return
}

// metric.HandlerBuilder#SetMetricTypes
func (b *builder) SetMetricTypes(types map[string]*metric.Type) {
	b.metricTypes = types
}

type saveableInstance struct {
	metric.Instance
}

func (s *saveableInstance) Save() (map[string]bigquery.Value, string, error) {
	id, _ := s.Dimensions["request_id"]
	insertID := id.(string)
	if insertID == "unknown" {
		insertID = strconv.FormatInt(time.Now().UnixNano(), 16)
	}

	row := make(map[string]bigquery.Value)
	row["name"] = s.Name
	row["value"] = s.Value
	for key, value := range s.Dimensions {
		row[key] = value
	}
	return row, insertID, nil
}

////////////////// Request-time Methods //////////////////////////
// metric.Handler#HandleMetric
func (h *handler) HandleMetric(ctx context.Context, insts []*metric.Instance) error {
	h.env.Logger().Infof("Handling Metric")
	storable := make([]*saveableInstance, 0, len(insts))
	for _, elem := range insts {
		sable := saveableInstance{Instance: *elem}
		m, id, _ := sable.Save()
		h.env.Logger().Infof("saveable %s %v", id, m)
		storable = append(storable, &sable)
	}

	if h.client != nil {
		myDataset := h.client.Dataset(h.dataset)
		table := myDataset.Table(h.table)
		uploader := table.Uploader()
		err := uploader.Put(ctx, storable)
		if err != nil {
			h.env.Logger().Warningf("Failed to write to bigquery: %v", err)
		}
	}

	var buffer bytes.Buffer
	for _, elem := range insts {
		mType, ok := h.metricTypes[elem.Name]
		if !ok {
			h.env.Logger().Errorf("Cannot find type for instance %s", elem.Name)
			continue
		}
		buffer.WriteString(fmt.Sprintf("Name: %s\nValue: %v\nType: %v\n", elem.Name, elem.Value, mType))
		keys := make([]string, 0, len(elem.Dimensions))
		for key := range elem.Dimensions {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			buffer.WriteString(fmt.Sprintf("  Dimension: %s %v\n", key, elem.Dimensions[key]))
		}
	}
	h.env.Logger().Infof(buffer.String())
	return nil
}

// adapter.Handler#Close
func (h *handler) Close() error {
	return h.client.Close()
}

// GetInfo returns the adapter.Info specific to this adapter.
////////////////// Bootstrap //////////////////////////
func GetInfo() adapter.Info {
	return adapter.Info{
		Name:        "secanalysis",
		Description: "Logs security info for later analysis",
		SupportedTemplates: []string{
			metric.TemplateName,
		},
		NewBuilder:    func() adapter.HandlerBuilder { return &builder{} },
		DefaultConfig: &config.Params{},
	}
}
