// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type watcherEventData struct {
	Pid  uint32
	Uid  uint32
	Comm [32]uint8
	Path [256]uint8
}

// loadWatcher returns the embedded CollectionSpec for watcher.
func loadWatcher() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_WatcherBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load watcher: %w", err)
	}

	return spec, err
}

// loadWatcherObjects loads watcher and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*watcherObjects
//	*watcherPrograms
//	*watcherMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadWatcherObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadWatcher()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// watcherSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type watcherSpecs struct {
	watcherProgramSpecs
	watcherMapSpecs
}

// watcherSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type watcherProgramSpecs struct {
	TracepointRmdir      *ebpf.ProgramSpec `ebpf:"tracepoint_rmdir"`
	TracepointSetsockopt *ebpf.ProgramSpec `ebpf:"tracepoint_setsockopt"`
	TracepointUnlink     *ebpf.ProgramSpec `ebpf:"tracepoint_unlink"`
	TracepointUnlinkat   *ebpf.ProgramSpec `ebpf:"tracepoint_unlinkat"`
}

// watcherMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type watcherMapSpecs struct {
	Events *ebpf.MapSpec `ebpf:"events"`
}

// watcherObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadWatcherObjects or ebpf.CollectionSpec.LoadAndAssign.
type watcherObjects struct {
	watcherPrograms
	watcherMaps
}

func (o *watcherObjects) Close() error {
	return _WatcherClose(
		&o.watcherPrograms,
		&o.watcherMaps,
	)
}

// watcherMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadWatcherObjects or ebpf.CollectionSpec.LoadAndAssign.
type watcherMaps struct {
	Events *ebpf.Map `ebpf:"events"`
}

func (m *watcherMaps) Close() error {
	return _WatcherClose(
		m.Events,
	)
}

// watcherPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadWatcherObjects or ebpf.CollectionSpec.LoadAndAssign.
type watcherPrograms struct {
	TracepointRmdir      *ebpf.Program `ebpf:"tracepoint_rmdir"`
	TracepointSetsockopt *ebpf.Program `ebpf:"tracepoint_setsockopt"`
	TracepointUnlink     *ebpf.Program `ebpf:"tracepoint_unlink"`
	TracepointUnlinkat   *ebpf.Program `ebpf:"tracepoint_unlinkat"`
}

func (p *watcherPrograms) Close() error {
	return _WatcherClose(
		p.TracepointRmdir,
		p.TracepointSetsockopt,
		p.TracepointUnlink,
		p.TracepointUnlinkat,
	)
}

func _WatcherClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed watcher_bpfel_x86.o
var _WatcherBytes []byte
