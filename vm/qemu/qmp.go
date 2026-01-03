// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package qemu

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/google/syzkaller/pkg/log"
)

type qmpVersion struct {
	Package string
	QEMU    struct {
		Major int
		Micro int
		Minor int
	}
}

type qmpBanner struct {
	QMP struct {
		Version qmpVersion
	}
}

type qmpCommand struct {
	Execute   string      `json:"execute"`
	Arguments interface{} `json:"arguments,omitempty"`
}

type hmpCommand struct {
	Command string `json:"command-line"`
	CPU     int    `json:"cpu-index"`
}

type qmpResponse struct {
	Error struct {
		Class string
		Desc  string
	}
	Return interface{}

	Event     string
	Data      map[string]interface{}
	Timestamp struct {
		Seconds      int64
		Microseconds int64
	}
}

// qmpReconnect closes the current QMP connection (if any) and establishes a new one.
// This is useful when the connection becomes stale or encounters errors.
func (inst *instance) qmpReconnect() error {
	if inst.mon != nil {
		inst.mon.Close()
		inst.mon = nil
		inst.monEnc = nil
		inst.monDec = nil
	}
	return inst.qmpConnCheck()
}

func (inst *instance) qmpConnCheck() error {
	if inst.mon != nil {
		return nil
	}

	addr := fmt.Sprintf("127.0.0.1:%v", inst.monport)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}

	monDec := json.NewDecoder(conn)
	monEnc := json.NewEncoder(conn)

	var banner qmpBanner
	if err := monDec.Decode(&banner); err != nil {
		conn.Close()
		return err
	}

	inst.monEnc = monEnc
	inst.monDec = monDec
	if _, err := inst.doQmp(&qmpCommand{Execute: "qmp_capabilities"}); err != nil {
		conn.Close()
		inst.monEnc = nil
		inst.monDec = nil
		return err
	}
	inst.mon = conn

	return nil
}

func (inst *instance) qmpRecv() (*qmpResponse, error) {
	for {
		qmp := new(qmpResponse)
		err := inst.monDec.Decode(qmp)
		if err != nil || qmp.Event == "" {
			return qmp, err
		}
		log.Logf(3, "event: %v", qmp)
	}
}

func (inst *instance) doQmp(cmd *qmpCommand) (*qmpResponse, error) {
	if err := inst.monEnc.Encode(cmd); err != nil {
		return nil, err
	}
	return inst.qmpRecv()
}

func (inst *instance) qmp(cmd *qmpCommand) (interface{}, error) {
	if err := inst.qmpConnCheck(); err != nil {
		return nil, err
	}
	resp, err := inst.doQmp(cmd)
	if err != nil {
		return nil, err
	}
	if resp.Error.Desc != "" {
		return nil, fmt.Errorf("%v", resp.Error)
	}
	if resp.Return == nil {
		return nil, fmt.Errorf(`no "return" nor "error" in [%v]`, resp)
	}
	if output, _ := resp.Return.(string); strings.HasPrefix(output, "Error:") ||
		strings.HasPrefix(output, "unknown command:") {
		return nil, errors.New(output)
	}
	return resp.Return, nil
}

func (inst *instance) hmp(cmd string, cpu int) (string, error) {
	if inst.debug {
		log.Logf(0, "qemu: running hmp command: %v", cmd)
	}
	req := &qmpCommand{
		Execute: "human-monitor-command",
		Arguments: &hmpCommand{
			Command: cmd,
			CPU:     cpu,
		},
	}
	resp, err := inst.qmp(req)
	if inst.debug {
		log.Logf(0, "qemu: reply: %v\n%v", err, resp)
	}
	if err != nil {
		return "", fmt.Errorf("qemu hmp command '%s': %w", cmd, err)
	}
	return resp.(string), nil
}

// SaveVMSnapshot saves the current VM state to a named snapshot using QEMU's savevm command.
// This requires the disk image to be in qcow2 format (not raw).
// The -snapshot flag must NOT be used for this to work properly.
func (inst *instance) SaveVMSnapshot(name string) error {
	log.Logf(0, "qemu: vm %d saving snapshot '%s'", inst.index, name)

	// First, check the current block device status
	infoOutput, infoErr := inst.hmp("info block", 0)
	if infoErr != nil {
		log.Logf(0, "qemu: vm %d failed to get block info: %v", inst.index, infoErr)
	} else {
		log.Logf(0, "qemu: vm %d block devices before savevm:\n%s", inst.index, infoOutput)
	}

	output, err := inst.hmp(fmt.Sprintf("savevm %s", name), 0)
	if err != nil {
		return fmt.Errorf("savevm failed: %w", err)
	}
	// Log the output regardless of debug mode to help diagnose snapshot issues
	log.Logf(0, "qemu: vm %d savevm output: '%s' (empty means success)", inst.index, output)

	if strings.Contains(output, "Error") || strings.Contains(output, "error") {
		return fmt.Errorf("savevm failed: %s", output)
	}

	// Verify the snapshot was actually saved by listing snapshots
	snapshotList, listErr := inst.hmp("info snapshots", 0)
	if listErr != nil {
		log.Logf(0, "qemu: vm %d failed to list snapshots after save: %v", inst.index, listErr)
	} else {
		log.Logf(0, "qemu: vm %d snapshots after save:\n%s", inst.index, snapshotList)
		// Check if our snapshot is in the list
		if !strings.Contains(snapshotList, name) {
			return fmt.Errorf("savevm claimed success but snapshot '%s' not found in snapshot list", name)
		}
	}

	log.Logf(0, "qemu: vm %d snapshot '%s' saved successfully", inst.index, name)
	return nil
}

// LoadVMSnapshot restores the VM state from a named snapshot using QEMU's loadvm command.
// After loading, all network connections (including SSH) will be broken and need to be re-established.
// Note: loadvm implicitly stops the VM and restores the CPU state from the snapshot.
func (inst *instance) LoadVMSnapshot(name string) error {
	if inst.debug {
		log.Logf(0, "qemu: loading VM snapshot: %s", name)
	}

	// Step 1: Stop the VM before loading snapshot to ensure consistent state
	// This is recommended by QEMU documentation to avoid issues during migration
	stopOutput, stopErr := inst.hmp("stop", 0)
	if stopErr != nil {
		log.Logf(1, "qemu: warning: failed to stop VM before loadvm: %v", stopErr)
		// Continue anyway, as loadvm might still work
	} else if inst.debug {
		log.Logf(0, "qemu: VM stopped, output: %s", stopOutput)
	}

	// Step 2: Load the snapshot
	output, err := inst.hmp(fmt.Sprintf("loadvm %s", name), 0)
	if err != nil {
		// If we get a connection error, the QEMU process may have crashed
		if strings.Contains(err.Error(), "closed") || strings.Contains(err.Error(), "connection") {
			log.Logf(1, "qemu: loadvm got connection error (QEMU may have crashed): %v", err)
			// Try to reconnect to see if QEMU is still alive
			if reconnErr := inst.qmpReconnect(); reconnErr != nil {
				return fmt.Errorf("loadvm failed (QEMU process likely crashed): loadvm error: %w, reconnect error: %v", err, reconnErr)
			}
			// If reconnection succeeded, QEMU is alive but loadvm may have partially completed
			// Try to resume the VM
			if _, contErr := inst.hmp("cont", 0); contErr != nil {
				log.Logf(1, "qemu: warning: failed to resume VM after loadvm error: %v", contErr)
			}
			return fmt.Errorf("loadvm failed but QEMU still running: %w", err)
		}
		// Resume VM and return error
		if _, contErr := inst.hmp("cont", 0); contErr != nil {
			log.Logf(1, "qemu: warning: failed to resume VM after loadvm error: %v", contErr)
		}
		return fmt.Errorf("loadvm failed: %w", err)
	}
	if strings.Contains(output, "Error") {
		// Resume VM and return error
		if _, contErr := inst.hmp("cont", 0); contErr != nil {
			log.Logf(1, "qemu: warning: failed to resume VM after loadvm error: %v", contErr)
		}
		return fmt.Errorf("loadvm failed: %s", output)
	}

	// Step 3: Resume the VM after successful loadvm
	// Note: loadvm restores the VM to its paused/running state at snapshot time,
	// but we explicitly resume to ensure it's running
	if _, contErr := inst.hmp("cont", 0); contErr != nil {
		log.Logf(1, "qemu: warning: failed to resume VM after loadvm: %v", contErr)
		// This might not be critical if the VM was running when snapshot was taken
	}

	if inst.debug {
		log.Logf(0, "qemu: snapshot loaded successfully: %s", name)
	}
	return nil
}
