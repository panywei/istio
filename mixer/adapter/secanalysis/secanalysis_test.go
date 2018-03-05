package secanalysis

import (
	"io"
	"log"
	"testing"

	"google.golang.org/grpc"

	"golang.org/x/net/context"

	"path/filepath"

	istio_mixer_v1 "istio.io/api/mixer/v1"
	"istio.io/istio/mixer/pkg/adapter"
	"istio.io/istio/mixer/pkg/attribute"
	"istio.io/istio/mixer/pkg/server"
	"istio.io/istio/mixer/template"
)

func TestSecAnalysysAdapter(t *testing.T) {
	operatorCnfg, err := filepath.Abs("operatorconfig")
	if err != nil {
		t.Fatalf("fail to get absolute path for operatorconfig: %v", err)
	}
	args := server.DefaultArgs()
	args.APIPort = 0
	args.MonitoringPort = 0
	args.ConfigStoreURL = `fs://` + operatorCnfg
	args.Templates = template.SupportedTmplInfo
	args.Adapters = []adapter.InfoFn{GetInfo}

	s, err := server.New(args)
	if err != nil {
		t.Fatalf("fail to create mixer: %v", err)
	}

	s.Run()
	defer closeHelper(s)

	conn, err := grpc.Dial(s.Addr().String(), grpc.WithInsecure())
	if err != nil {
		t.Fatalf("Unable to connect to gRPC server: %v", err)
	}

	client := istio_mixer_v1.NewMixerClient(conn)
	defer closeHelper(conn)

	attrs := map[string]interface{}{"response.code": int64(400)}
	req := istio_mixer_v1.ReportRequest{
		Attributes: []istio_mixer_v1.CompressedAttributes{
			getAttrBag(attrs,
				args.ConfigIdentityAttribute,
				args.ConfigIdentityAttributeDomain)},
	}
	_, err = client.Report(context.Background(), &req)
	if err != nil {
		t.Errorf("fail to send report to Mixer %v", err)
	}
}

func closeHelper(c io.Closer) {
	err := c.Close()
	if err != nil {
		log.Fatal(err)
	}
}

func getAttrBag(attrs map[string]interface{}, identityAttr, identityAttrDomain string) istio_mixer_v1.CompressedAttributes {
	requestBag := attribute.GetMutableBag(nil)
	requestBag.Set(identityAttr, identityAttrDomain)
	for k, v := range attrs {
		requestBag.Set(k, v)
	}

	var attrProto istio_mixer_v1.CompressedAttributes
	requestBag.ToProto(&attrProto, nil, 0)
	return attrProto
}
