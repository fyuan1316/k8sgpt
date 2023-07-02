/*
Copyright 2023 The K8sGPT Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package analyzer

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
	"github.com/k8sgpt-ai/k8sgpt/pkg/util"
	"github.com/mitchellh/go-homedir"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	asmoperatorv1alpha1 "gomod.alauda.cn/asm/api/operator/v1alpha1"
)

type ServiceMeshAnalyzer struct {
	client.Client
}

func (s *ServiceMeshAnalyzer) init() {
	cfg, err := config.GetConfig()
	if err != nil {
		home, err := homedir.Dir()
		if err == nil {
			cfg, err = clientcmd.BuildConfigFromFlags("", filepath.Join(home, ".kube/config"))
			if err != nil {
				panic(err)
			}
		} else {
			panic(err)
		}
	}
	scheme := runtime.NewScheme()
	utilruntime.Must(asmoperatorv1alpha1.AddToScheme(scheme))
	clt, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		panic(err)
	}
	s.Client = clt
}
func (s *ServiceMeshAnalyzer) Analyze(a common.Analyzer) ([]common.Result, error) {
	s.init()
	kind := "ServiceMesh"

	AnalyzerErrorsMetric.DeletePartialMatch(map[string]string{
		"analyzer_name": kind,
	})

	// search all namespaces for pods that are not running
	meshList := &asmoperatorv1alpha1.ServiceMeshList{}
	err := s.Client.List(context.Background(), meshList, &client.ListOptions{Namespace: "cpaas-system"})
	if err != nil {
		return nil, err
	}
	var preAnalysis = map[string]common.PreAnalysis{}

	for _, sm := range meshList.Items {
		var failures []common.Failure
		// Check for pending pods
		if sm.Status.Phase == asmoperatorv1alpha1.Failed {
			failures = append(failures, common.Failure{
				Text:      sm.Status.Message,
				Sensitive: []common.Sensitive{},
			})
			if len(failures) > 0 {
				preAnalysis[fmt.Sprintf("%s/%s", sm.Namespace, sm.Name)] = common.PreAnalysis{
					ServiceMesh:    &sm,
					FailureDetails: failures,
				}
				AnalyzerErrorsMetric.WithLabelValues(kind, sm.Name, sm.Namespace).Set(float64(len(failures)))
			}
		}
	}

	for key, value := range preAnalysis {
		var currentAnalysis = common.Result{
			Kind:    kind,
			Name:    key,
			Error:   value.FailureDetails,
			Subject: value.ServiceMesh.GroupVersionKind().Group,
		}

		parent, _ := util.GetParent(a.Client, value.Pod.ObjectMeta)
		currentAnalysis.ParentObject = parent
		a.Results = append(a.Results, currentAnalysis)
	}

	return a.Results, nil
}
