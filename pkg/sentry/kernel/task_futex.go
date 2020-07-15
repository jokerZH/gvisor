// Copyright 2018 The gVisor Authors.
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

package kernel

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/kernel/futex"
	"gvisor.dev/gvisor/pkg/usermem"
)

// Futex returns t's futex manager.
//
// Preconditions: The caller must be running on the task goroutine, or t.mu
// must be locked.
func (t *Task) Futex() *futex.Manager {
	return t.tc.fu
}

// SwapUint32 implements futex.Target.SwapUint32.
func (t *Task) SwapUint32(addr usermem.Addr, new uint32) (uint32, error) {
	return t.MemoryManager().SwapUint32(t, addr, new, usermem.IOOpts{
		AddressSpaceActive: true,
	})
}

// CompareAndSwapUint32 implements futex.Target.CompareAndSwapUint32.
func (t *Task) CompareAndSwapUint32(addr usermem.Addr, old, new uint32) (uint32, error) {
	return t.MemoryManager().CompareAndSwapUint32(t, addr, old, new, usermem.IOOpts{
		AddressSpaceActive: true,
	})
}

// LoadUint32 implements futex.Target.LoadUint32.
func (t *Task) LoadUint32(addr usermem.Addr) (uint32, error) {
	return t.MemoryManager().LoadUint32(t, addr, usermem.IOOpts{
		AddressSpaceActive: true,
	})
}

// GetSharedKey implements futex.Target.GetSharedKey.
func (t *Task) GetSharedKey(addr usermem.Addr) (futex.Key, error) {
	return t.MemoryManager().GetSharedFutexKey(t, addr)
}

// GetRobustList sets the robust futex list for the task.
func (t *Task) GetRobustList() usermem.Addr {
	t.mu.Lock()
	addr := t.robustList
	t.mu.Unlock()
	return addr
}

// SetRobustList sets the robust futex list for the task.
func (t *Task) SetRobustList(addr usermem.Addr) {
	t.mu.Lock()
	t.robustList = addr
	t.mu.Unlock()
}

// exitRobustList walks the robust futex list, marking locks dead and notifying
// wakers. It corresponds to Linux's exit_robust_list(). Following Linux,
// errors are silently ignored.
func (t *Task) exitRobustList() {
	t.mu.Lock()
	addr := t.robustList
	t.robustList = 0
	t.mu.Unlock()

	if addr == 0 {
		return
	}

	var rl linux.RobustListHead
	if _, err := t.CopyIn(usermem.Addr(addr), &rl); err != nil {
		return
	}

	next := rl.List
	done := 0
	var pendingLock usermem.Addr
	if rl.ListOpPending != 0 {
		pendingLock = usermem.Addr(rl.ListOpPending + rl.FutexOffset)
	}

	// Wake up normal elements.
	for usermem.Addr(next) != addr {
		// We traverse to the next element of the list before we
		// actually wake anything. This prevents the race where waking
		// this futex causes a modification of the list.
		thisLock := usermem.Addr(next + rl.FutexOffset)

		// Decode the next element in the list.
		if _, err := t.CopyIn(usermem.Addr(next), &next); err != nil {
			// Can't traverse the list anymore? We need to bail
			// out at this point.
			break
		}

		// Perform the wakeup if it's not pending.
		if thisLock != pendingLock {
			t.wakeRobustListOne(thisLock)
		}

		// This is a user structure, so it could be a massive list, or
		// even contain a loop if they are trying to mess with us. We
		// cap traversal to prevent that.
		done++
		if done >= linux.ROBUST_LIST_LIMIT {
			break
		}
	}

	// Is there a pending entry to wake?
	if pendingLock != 0 {
		t.wakeRobustListOne(pendingLock)
	}
}

// wakeRobustListOne wakes a single futex from the robust list.
func (t *Task) wakeRobustListOne(addr usermem.Addr) {
	tid := uint32(t.ThreadID())
	for {
		// Load the futex.
		f, err := t.LoadUint32(addr)
		if err != nil {
			// Can't read this single value? Ignore the problem.
			// We can wake the other futexes in the list.
			return
		}

		// Is this held by someone else?
		if f&linux.FUTEX_TID_MASK != uint32(tid) {
			return
		}

		// This thread is dying and it's holding this futex. We need to
		// set the owner died bit and wake up any waiters.
		newF := (f & linux.FUTEX_WAITERS) | linux.FUTEX_OWNER_DIED
		if curF, err := t.CompareAndSwapUint32(addr, f, newF); err != nil {
			return
		} else if curF != f {
			// Try again.
			continue
		}

		// Wake waiters if there are any.
		if f&linux.FUTEX_WAITERS != 0 {
			private := f&linux.FUTEX_PRIVATE_FLAG != 0
			t.Futex().Wake(t, addr, private, linux.FUTEX_BITSET_MATCH_ANY, 1)
		}
	}
}
