// Copyright 2017 Istio Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package convert

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/ghodss/yaml"
	multierror "github.com/hashicorp/go-multierror"
	"github.com/spf13/cobra"
	"k8s.io/api/extensions/v1beta1"

	"istio.io/istio/istioctl/pkg/convert"
	"istio.io/istio/pilot/pkg/config/kube/crd"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/log"
)

var (
	inFilenames []string
	outFilename string
)

// Command for converting v1alpha1 configs to v1alpha3
func Command() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "convert-networking-config",
		Short: "Convert networking configs from v1alpha1 to v1alpha3",
		Long: "Converts sets of v1alpha1 configs to v1alpha3 equivalents on a best effort basis. " +
			"The output should be considered a starting point for your v1alpha3 configs and probably " +
			"require some minor modification. " +
			"Warnings will (hopefully) be generated where configs cannot be converted perfectly, " +
			"or in certain edge cases. " +
			"The input must be the set of configs that would be in place in an environment at a given " +
			"time. " +
			"This allows the command to attempt to create and merge output configs intelligently." +
			"Output configs are given the namespace and domain of the first input config " +
			"so it is recommended that input configs be part of the same namespace and domain.",
		Example: "istioctl experimental convert-networking-config -f v1alpha1/default-route.yaml -f v1alpha1/header-delay.yaml",
		RunE: func(c *cobra.Command, args []string) error {
			if len(inFilenames) == 0 {
				return fmt.Errorf("no input files provided")
			}

			readers := make([]io.Reader, 0)
			if len(inFilenames) == 1 && inFilenames[0] == "-" {
				readers = append(readers, os.Stdin)
			} else {
				for _, filename := range inFilenames {
					file, err := os.Open(filename)
					if err != nil {
						return err
					}
					defer func() {
						if err := file.Close(); err != nil {
							log.Errorf("Did not close input %s successfully: %v",
								filename, err)
						}
					}()
					readers = append(readers, file)
				}
			}

			writer := os.Stdout
			if outFilename != "-" {
				file, err := os.Create(outFilename)
				if err != nil {
					return err
				}
				defer func() {
					if err := file.Close(); err != nil {
						log.Errorf("Did not close output successfully: %v", err)
					}
				}()

				writer = file
			}

			return convertConfigs(readers, writer)
		},
	}

	cmd.PersistentFlags().StringSliceVarP(&inFilenames, "filenames", "f",
		nil, "Input filenames")
	cmd.PersistentFlags().StringVarP(&outFilename, "output", "o",
		"-", "Output filename")

	return cmd
}

func convertConfigs(readers []io.Reader, writer io.Writer) error {
	configDescriptor := model.ConfigDescriptor{
		model.RouteRule,
		model.VirtualService,
		model.Gateway,
		model.EgressRule,
		model.ServiceEntry,
		model.DestinationPolicy,
		model.DestinationRule,
		model.HTTPAPISpec,
		model.HTTPAPISpecBinding,
		model.QuotaSpec,
		model.QuotaSpecBinding,
	}

	configs, ingresses, err := readConfigs(readers)
	if err != nil {
		return err
	}

	if err = validateConfigs(configs); err != nil {
		return err
	}

	out := make([]model.Config, 0)
	out = append(out, convert.DestinationPolicies(configs)...)
	out = append(out, convert.RouteRules(configs)...)
	out = append(out, convert.EgressRules(configs)...)
	convertedIngresses, err := convert.IstioIngresses(ingresses, "")
	if err == nil {
		out = append(out, convertedIngresses...)
	} else {
		return multierror.Prefix(err, "Ingress rules invalid")
	}
	out = append(out, convert.RouteRuleRouteLabels(out, configs)...)

	writeYAMLOutput(configDescriptor, out, writer)

	// sanity check that the outputs are valid
	if err := validateConfigs(out); err != nil {
		return multierror.Prefix(err, "output config(s) are invalid:")
	}
	return nil
}

func readConfigs(readers []io.Reader) ([]model.Config, []*v1beta1.Ingress, error) {
	out := make([]model.Config, 0)
	outIngresses := make([]*v1beta1.Ingress, 0)

	for _, reader := range readers {
		data, err := ioutil.ReadAll(reader)
		if err != nil {
			return nil, nil, err
		}

		configs, kinds, err := crd.ParseInputs(string(data))
		if err != nil {
			return nil, nil, err
		}

		recognized := 0
		for _, nonIstio := range kinds {
			if nonIstio.Kind == "Ingress" &&
				nonIstio.APIVersion == "extensions/v1beta1" {

				ingress, err := parseIngress(nonIstio)
				if err != nil {
					log.Errorf("Could not decode ingress %v: %v", nonIstio.Name, err)
					continue
				}

				outIngresses = append(outIngresses, ingress)
				recognized++
			}
		}

		if len(kinds) > recognized {
			// If convert-networking-config was asked to convert non-network things,
			// like Deployments and Services, return a brief informative error
			kindsFound := make(map[string]bool)
			for _, kind := range kinds {
				kindsFound[kind.Kind] = true
			}

			var msg error
			for kind := range kindsFound {
				msg = multierror.Append(msg, fmt.Errorf("unsupported kind: %v", kind))
			}

			return nil, nil, msg
		}

		out = append(out, configs...)
	}
	return out, outIngresses, nil
}

func writeYAMLOutput(descriptor model.ConfigDescriptor, configs []model.Config, writer io.Writer) {
	for i, config := range configs {
		schema, exists := descriptor.GetByType(config.Type)
		if !exists {
			log.Errorf("Unknown kind %q for %v", crd.ResourceName(config.Type), config.Name)
			continue
		}
		obj, err := crd.ConvertConfig(schema, config)
		if err != nil {
			log.Errorf("Could not decode %v: %v", config.Name, err)
			continue
		}
		bytes, err := yaml.Marshal(obj)
		if err != nil {
			log.Errorf("Could not convert %v to YAML: %v", config, err)
			continue
		}
		writer.Write(bytes) // nolint: errcheck
		if i+1 < len(configs) {
			writer.Write([]byte("---\n")) // nolint: errcheck
		}
	}
}

func validateConfigs(configs []model.Config) error {
	var errs error
	for _, config := range configs {
		var err error
		switch config.Type {
		case model.RouteRule.Type:
			err = model.ValidateRouteRule(config.Spec)
		case model.VirtualService.Type:
			err = model.ValidateVirtualService(config.Spec)
		case model.Gateway.Type:
			err = model.ValidateGateway(config.Spec)
		case model.EgressRule.Type:
			err = model.ValidateEgressRule(config.Spec)
		case model.ServiceEntry.Type:
			err = model.ValidateServiceEntry(config.Spec)
		case model.DestinationPolicy.Type:
			err = model.ValidateDestinationPolicy(config.Spec)
		case model.DestinationRule.Type:
			err = model.ValidateDestinationRule(config.Spec)
		}
		if err != nil {
			errs = multierror.Append(err, errs)
		}
	}
	return errs
}

func parseIngress(unparsed crd.IstioKind) (*v1beta1.Ingress, error) {
	// To convert unparsed to a v1beta1.Ingress Marshal into JSON and Unmarshal back
	b, err := json.Marshal(unparsed)
	if err != nil {
		return nil, multierror.Prefix(err, "can't reserialize Ingress")
	}

	out := &v1beta1.Ingress{}
	err = json.Unmarshal(b, out)
	if err != nil {
		return nil, multierror.Prefix(err, "can't deserialize as Ingress")
	}

	return out, nil
}
