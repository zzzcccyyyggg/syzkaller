// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ddrd

// ID returns the stable identifier assigned to the basic UAF pair.
func (pair *MayUAFPair) ID() uint64 {
	if pair == nil {
		return 0
	}
	return pair.UAFPairID()
}

// ID returns identifier of the extended pair, falling back to the basic pair
// identity when necessary.
func (pair *ExtendedUAFPair) ID() uint64 {
	if pair == nil {
		return 0
	}
	return pair.BasicInfo.UAFPairID()
}
