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
	"fmt"

	"istio.io/api/networking/v1alpha3"
	"istio.io/api/routing/v1alpha1"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/log"
)

// EgressRules converts v1alpha1 egress rules to v1alpha3 service entries
func EgressRules(configs []model.Config) []model.Config {
	egressRules := make([]*v1alpha1.EgressRule, 0)
	for _, config := range configs {
		if config.Type == model.EgressRule.Type {
			egressRules = append(egressRules, config.Spec.(*v1alpha1.EgressRule))
		}
	}

	serviceEntries := make([]*v1alpha3.ServiceEntry, 0)
	for _, egressRule := range egressRules {
		host := convertIstioService(egressRule.Destination)

		ports := make([]*v1alpha3.Port, 0)
		for _, egressPort := range egressRule.Ports {
			ports = append(ports, &v1alpha3.Port{
				Name:     fmt.Sprintf("%s-%d", egressPort.Protocol, egressPort.Port),
				Protocol: egressPort.Protocol,
				Number:   uint32(egressPort.Port),
			})
		}

		if egressRule.UseEgressProxy {
			log.Warnf("Use egress proxy field not supported")
		}

		serviceEntries = append(serviceEntries, &v1alpha3.ServiceEntry{
			Hosts:      []string{host},
			Ports:      ports,
			Resolution: v1alpha3.ServiceEntry_NONE,
		})
	}

	out := make([]model.Config, 0)
	for _, serviceEntry := range serviceEntries {
		out = append(out, model.Config{
			ConfigMeta: model.ConfigMeta{
				Type:      model.ServiceEntry.Type,
				Name:      serviceEntry.Hosts[0],
				Namespace: configs[0].Namespace,
				Domain:    configs[0].Domain,
			},
			Spec: serviceEntry,
		})
	}

	return out
}
