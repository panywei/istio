//  Copyright 2018 Istio Authors
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package resource

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic/fake"
	dtesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"

	"istio.io/istio/galley/pkg/change"
	"istio.io/istio/galley/pkg/testing/common"
	"istio.io/istio/galley/pkg/testing/mock"
)

func TestAccessor_NewClientError(t *testing.T) {
	k := &mock.Kube{}
	k.AddResponse(nil, errors.New("newDynamicClient error"))

	gv := schema.GroupVersion{Group: "group", Version: "version"}
	processorFn := func(c *change.Info) {}

	_, err := newAccessor(k, 0, "foo", gv, "kind", "listkind", processorFn)
	if err == nil || err.Error() != "newDynamicClient error" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAccessor_Basic(t *testing.T) {
	k := mock.NewKube()
	cl := &fake.FakeClient{
		Fake: &dtesting.Fake{},
	}
	k.AddResponse(cl, nil)

	gv := schema.GroupVersion{Group: "group", Version: "version"}
	processorLog := &common.MockLog{}
	processorFn := func(c *change.Info) { processorLog.Append("%v", c) }

	cl.AddReactor("*", "foo", func(action dtesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, &unstructured.UnstructuredList{Items: []unstructured.Unstructured{}}, nil
	})
	cl.AddWatchReactor("foo", func(action dtesting.Action) (handled bool, ret watch.Interface, err error) {
		return true, mock.NewWatch(), nil
	})

	a, err := newAccessor(k, 0, "foo", gv, "kind", "listkind", processorFn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer a.stop()
	a.start()

	expected := `
list foo
watch foo
`
	check(t, writeActions(cl.Fake.Actions()), expected)
	check(t, processorLog.String(), "")
}

func TestAccessor_DoubleStart(t *testing.T) {
	k := mock.NewKube()
	cl := &fake.FakeClient{
		Fake: &dtesting.Fake{},
	}
	k.AddResponse(cl, nil)

	gv := schema.GroupVersion{Group: "group", Version: "version"}
	processorLog := &common.MockLog{}
	processorFn := func(c *change.Info) { processorLog.Append("%v", c) }

	cl.AddReactor("*", "foo", func(action dtesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, &unstructured.UnstructuredList{Items: []unstructured.Unstructured{}}, nil
	})
	cl.AddWatchReactor("foo", func(action dtesting.Action) (handled bool, ret watch.Interface, err error) {
		return true, mock.NewWatch(), nil
	})

	a, err := newAccessor(k, 0, "foo", gv, "kind", "listkind", processorFn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer a.stop()

	a.start()
	a.start()

	expected := `
list foo
watch foo
`
	check(t, writeActions(cl.Fake.Actions()), expected)
	check(t, processorLog.String(), "")
}

func TestAccessor_DoubleStop(t *testing.T) {
	k := mock.NewKube()
	cl := &fake.FakeClient{
		Fake: &dtesting.Fake{},
	}
	k.AddResponse(cl, nil)

	gv := schema.GroupVersion{Group: "group", Version: "version"}
	processorLog := &common.MockLog{}
	processorFn := func(c *change.Info) { processorLog.Append("%v", c) }

	cl.AddReactor("*", "foo", func(action dtesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, &unstructured.UnstructuredList{Items: []unstructured.Unstructured{}}, nil
	})
	cl.AddWatchReactor("foo", func(action dtesting.Action) (handled bool, ret watch.Interface, err error) {
		return true, mock.NewWatch(), nil
	})

	a, err := newAccessor(k, 0, "foo", gv, "kind", "listkind", processorFn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	a.start()
	a.stop()
	a.stop()

	expected := `
list foo
watch foo
`
	check(t, writeActions(cl.Fake.Actions()), expected)
	check(t, processorLog.String(), "")
}

func TestAccessor_AddEvent(t *testing.T) {
	k := mock.NewKube()
	cl := &fake.FakeClient{
		Fake: &dtesting.Fake{},
	}
	k.AddResponse(cl, nil)

	gv := schema.GroupVersion{Group: "group", Version: "version"}
	processorLog := &common.MockLog{}
	wg := &sync.WaitGroup{}
	wg.Add(1)
	processorFn := func(c *change.Info) {
		processorLog.Append("%v", c)
		wg.Done()
	}

	cl.AddReactor("*", "foo", func(action dtesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, &unstructured.UnstructuredList{Items: []unstructured.Unstructured{}}, nil
	})
	w := mock.NewWatch()
	cl.AddWatchReactor("foo", func(action dtesting.Action) (handled bool, ret watch.Interface, err error) {
		return true, w, nil
	})

	a, err := newAccessor(k, 0, "foo", gv, "kind", "listkind", processorFn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer a.stop()

	a.start()

	w.Send(watch.Event{Type: watch.Added, Object: template.DeepCopy()})
	wg.Wait()

	expected := `
list foo
watch foo
`
	check(t, writeActions(cl.Fake.Actions()), expected)

	expected = `
Info[Type:Add, Name:foo, GroupVersion:group/version]`

	check(t, processorLog.String(), expected)
}

func TestAccessor_UpdateEvent(t *testing.T) {
	k := mock.NewKube()
	cl := &fake.FakeClient{
		Fake: &dtesting.Fake{},
	}
	k.AddResponse(cl, nil)

	gv := schema.GroupVersion{Group: "group", Version: "version"}
	processorLog := &common.MockLog{}
	wg := &sync.WaitGroup{}
	wg.Add(2) // One for initial add, one for update
	processorFn := func(c *change.Info) {
		processorLog.Append("%v", c)
		wg.Done()
	}

	cl.AddReactor("*", "foo", func(action dtesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, &unstructured.UnstructuredList{Items: []unstructured.Unstructured{*template.DeepCopy()}}, nil
	})
	w := mock.NewWatch()
	cl.AddWatchReactor("foo", func(action dtesting.Action) (handled bool, ret watch.Interface, err error) {
		return true, w, nil
	})

	a, err := newAccessor(k, 0, "foo", gv, "kind", "listkind", processorFn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer a.stop()

	a.start()

	t2 := template.DeepCopy()
	t2.SetResourceVersion("rv2")
	w.Send(watch.Event{Type: watch.Modified, Object: t2})
	wg.Wait()

	expected := `
list foo
watch foo
`
	check(t, writeActions(cl.Fake.Actions()), expected)

	expected = `
Info[Type:Add, Name:foo, GroupVersion:group/version]
Info[Type:Update, Name:foo, GroupVersion:group/version]`

	check(t, processorLog.String(), expected)
}

func TestAccessor_UpdateEvent_SameResourceVersion(t *testing.T) {
	k := mock.NewKube()
	cl := &fake.FakeClient{
		Fake: &dtesting.Fake{},
	}
	k.AddResponse(cl, nil)

	gv := schema.GroupVersion{Group: "group", Version: "version"}
	processorLog := &common.MockLog{}
	wg := &sync.WaitGroup{}
	wg.Add(1) // One for initial add only
	processorFn := func(c *change.Info) {
		processorLog.Append("%v", c)
		wg.Done()
	}

	cl.AddReactor("*", "foo", func(action dtesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, &unstructured.UnstructuredList{Items: []unstructured.Unstructured{*template.DeepCopy()}}, nil
	})
	w := mock.NewWatch()
	cl.AddWatchReactor("foo", func(action dtesting.Action) (handled bool, ret watch.Interface, err error) {
		return true, w, nil
	})

	a, err := newAccessor(k, 0, "foo", gv, "kind", "listkind", processorFn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer a.stop()

	a.start()

	t2 := template.DeepCopy()
	w.Send(watch.Event{Type: watch.Modified, Object: t2})
	wg.Wait()

	expected := `
list foo
watch foo
`
	check(t, writeActions(cl.Fake.Actions()), expected)

	expected = `
Info[Type:Add, Name:foo, GroupVersion:group/version]
`
	check(t, processorLog.String(), expected)
}

func TestAccessor_DeleteEvent(t *testing.T) {
	k := mock.NewKube()
	cl := &fake.FakeClient{
		Fake: &dtesting.Fake{},
	}
	k.AddResponse(cl, nil)

	gv := schema.GroupVersion{Group: "group", Version: "version"}
	processorLog := &common.MockLog{}
	wg := &sync.WaitGroup{}
	wg.Add(2) // One for initial add, one for delete
	processorFn := func(c *change.Info) {
		processorLog.Append("%v", c)
		wg.Done()
	}

	cl.AddReactor("*", "foo", func(action dtesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, &unstructured.UnstructuredList{Items: []unstructured.Unstructured{*template.DeepCopy()}}, nil
	})
	w := mock.NewWatch()
	cl.AddWatchReactor("foo", func(action dtesting.Action) (handled bool, ret watch.Interface, err error) {
		return true, w, nil
	})

	a, err := newAccessor(k, 0, "foo", gv, "kind", "listkind", processorFn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer a.stop()

	a.start()

	t2 := template.DeepCopy()
	t2.SetResourceVersion("rv2")
	w.Send(watch.Event{Type: watch.Deleted, Object: t2})
	wg.Wait()

	expected := `
list foo
watch foo
`
	check(t, writeActions(cl.Fake.Actions()), expected)

	expected = `
Info[Type:Add, Name:foo, GroupVersion:group/version]
Info[Type:Delete, Name:foo, GroupVersion:group/version]`
	check(t, processorLog.String(), expected)
}

func TestAccessor_Tombstone(t *testing.T) {
	k := mock.NewKube()
	cl := &fake.FakeClient{
		Fake: &dtesting.Fake{},
	}
	k.AddResponse(cl, nil)

	gv := schema.GroupVersion{Group: "group", Version: "version"}
	processorLog := &common.MockLog{}
	wg := &sync.WaitGroup{}
	wg.Add(2) // One for initial add, one for delete
	processorFn := func(c *change.Info) {
		processorLog.Append("%v", c)
		wg.Done()
	}

	cl.AddReactor("*", "foo", func(action dtesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, &unstructured.UnstructuredList{Items: []unstructured.Unstructured{*template.DeepCopy()}}, nil
	})
	w := mock.NewWatch()
	cl.AddWatchReactor("foo", func(action dtesting.Action) (handled bool, ret watch.Interface, err error) {
		return true, w, nil
	})

	a, err := newAccessor(k, 0, "foo", gv, "kind", "listkind", processorFn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer a.stop()

	a.start()

	t2 := template.DeepCopy()
	item := cache.DeletedFinalStateUnknown{Key: "foo", Obj: t2}
	a.handleEvent(change.Delete, item)

	wg.Wait()

	expected := `
list foo
watch foo
`
	check(t, writeActions(cl.Fake.Actions()), expected)

	expected = `
Info[Type:Add, Name:foo, GroupVersion:group/version]
Info[Type:Delete, Name:foo, GroupVersion:group/version]`
	check(t, processorLog.String(), expected)
}

func TestAccessor_TombstoneDecodeError(t *testing.T) {
	k := mock.NewKube()
	cl := &fake.FakeClient{
		Fake: &dtesting.Fake{},
	}
	k.AddResponse(cl, nil)

	gv := schema.GroupVersion{Group: "group", Version: "version"}
	processorLog := &common.MockLog{}
	wg := &sync.WaitGroup{}
	wg.Add(1) // One for initial add only
	processorFn := func(c *change.Info) {
		processorLog.Append("%v", c)
		wg.Done()
	}

	cl.AddReactor("*", "foo", func(action dtesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, &unstructured.UnstructuredList{Items: []unstructured.Unstructured{*template.DeepCopy()}}, nil
	})
	w := mock.NewWatch()
	cl.AddWatchReactor("foo", func(action dtesting.Action) (handled bool, ret watch.Interface, err error) {
		return true, w, nil
	})

	a, err := newAccessor(k, 0, "foo", gv, "kind", "listkind", processorFn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer a.stop()

	a.start()

	a.handleEvent(change.Delete, struct{}{})

	wg.Wait()

	expected := `
list foo
watch foo
`
	check(t, writeActions(cl.Fake.Actions()), expected)

	expected = `
Info[Type:Add, Name:foo, GroupVersion:group/version]
`
	check(t, processorLog.String(), expected)
}

func TestAccessor_Tombstone_ObjDecodeError(t *testing.T) {
	k := mock.NewKube()
	cl := &fake.FakeClient{
		Fake: &dtesting.Fake{},
	}
	k.AddResponse(cl, nil)

	gv := schema.GroupVersion{Group: "group", Version: "version"}
	processorLog := &common.MockLog{}
	wg := &sync.WaitGroup{}
	wg.Add(1) // One for initial add only
	processorFn := func(c *change.Info) {
		processorLog.Append("%v", c)
		wg.Done()
	}
	cl.AddReactor("*", "foo", func(action dtesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, &unstructured.UnstructuredList{Items: []unstructured.Unstructured{*template.DeepCopy()}}, nil
	})
	w := mock.NewWatch()
	cl.AddWatchReactor("foo", func(action dtesting.Action) (handled bool, ret watch.Interface, err error) {
		return true, w, nil
	})

	a, err := newAccessor(k, 0, "foo", gv, "kind", "listkind", processorFn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer a.stop()

	a.start()

	item := cache.DeletedFinalStateUnknown{Key: "foo", Obj: struct{}{}}
	a.handleEvent(change.Delete, item)

	wg.Wait()

	expected := `
list foo
watch foo
`
	check(t, writeActions(cl.Fake.Actions()), expected)

	expected = `
Info[Type:Add, Name:foo, GroupVersion:group/version]
`
	check(t, processorLog.String(), expected)
}

var template = &unstructured.Unstructured{
	Object: map[string]interface{}{
		"metadata": map[string]interface{}{
			"name":            "foo",
			"resourceVersion": "rv",
		},
	},
}

func writeActions(actions []dtesting.Action) string {
	result := ""
	for _, a := range actions {
		result += fmt.Sprintf("%s %s\n", a.GetVerb(), a.GetResource().Resource)
	}
	return result
}
