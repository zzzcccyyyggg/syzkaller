// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
	uafvalidate "github.com/google/syzkaller/pkg/racevalidate"
	"github.com/google/syzkaller/vm"
	"github.com/google/syzkaller/vm/dispatcher"
)

// raceValidateExecutorFactory creates an ExecutorFactory that acquires VMs
// from the dispatcher pool's reserved slots (same mechanism as crash repro)
// and wraps them as uafvalidate.Executor for StageManager to use.
//
// Each call to the returned factory:
//  1. Starts a background pool.Run() goroutine that acquires a reserved VM
//  2. Sets up ExecProg on the VM
//  3. Returns a pooledRaceExecutor that wraps ExecutorAdapter
//  4. When the executor is Close()'d, the pool.Run callback returns → VM released
//
// This bridges the dispatcher pool's callback model with StageManager's
// ExecutorFactory return-value model.
func (mgr *Manager) raceValidateExecutorFactory(cfg uafvalidate.Config) uafvalidate.ExecutorFactory {
	return func(ctx context.Context) (uafvalidate.Executor, error) {
		type execResult struct {
			exec uafvalidate.Executor
			err  error
		}
		ready := make(chan execResult, 1)
		done := make(chan struct{})

		go func() {
			runErr := mgr.pool.Run(ctx, func(ctx context.Context, inst *vm.Instance, updInfo dispatcher.UpdateInfo) {
				updInfo(func(info *dispatcher.Info) {
					info.Status = "race-validate: setup"
				})

				execInst, err := instance.SetupExecProg(inst, mgr.cfg, mgr.reporter, nil)
				if err != nil {
					ready <- execResult{err: fmt.Errorf("race-validate: setup execprog: %w", err)}
					return
				}

				adapter := uafvalidate.NewExecutorAdapter(execInst, cfg)
				pooled := &pooledRaceExecutor{
					ExecutorAdapter: adapter,
					done:            done,
					updInfo:         updInfo,
				}

				log.Logf(1, "[RACE-VALIDATE] VM acquired (index=%d), executor ready", inst.Index())
				ready <- execResult{exec: pooled}

				// Block until the executor is closed by StageManager worker.
				// When Close() is called, 'done' is closed, this unblocks,
				// pool.Run callback returns → VM released back to dispatcher.
				<-done
				log.Logf(1, "[RACE-VALIDATE] VM released (index=%d)", inst.Index())
			})
			if runErr != nil {
				// pool.Run failed to acquire a VM (e.g. no reserved VMs available)
				select {
				case ready <- execResult{err: fmt.Errorf("race-validate: pool.Run: %w", runErr)}:
				default:
				}
			}
		}()

		select {
		case res := <-ready:
			return res.exec, res.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// pooledRaceExecutor wraps ExecutorAdapter, and on Close() signals
// the pool.Run callback to return (releasing the VM).
type pooledRaceExecutor struct {
	*uafvalidate.ExecutorAdapter
	done      chan struct{}
	updInfo   dispatcher.UpdateInfo
	closeOnce sync.Once
}

func (p *pooledRaceExecutor) Close() error {
	var err error
	p.closeOnce.Do(func() {
		// Close the underlying executor adapter (shuts down RPC connections).
		err = p.ExecutorAdapter.Close()
		// Signal pool.Run callback to return → releases VM.
		close(p.done)
	})
	return err
}
