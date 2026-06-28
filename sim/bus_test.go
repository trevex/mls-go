package sim

import "testing"

// TestBusFanout verifies Publish(broadcast) schedules one deliver per subscriber
// (excluding the source); Dst != Broadcast schedules exactly one.
func TestBusFanout(t *testing.T) {
	s := NewScheduler(1)
	f := newFaultState(FaultConfig{Latency: 1}) // latency=1 so all events schedule
	m := newMetrics()
	b := newBus(s, f, m)

	// register 4 subscribers on VNI 100
	for _, a := range []ActorID{0, 1, 2, 3} {
		b.Subscribe(100, a)
	}

	// broadcast from actor 0 → should deliver to 1, 2, 3 (not 0)
	b.Publish(Envelope{VNI: 100, Type: MsgCommit, Src: 0, Dst: Broadcast})
	if m.Delivered != 3 {
		t.Fatalf("broadcast: expected 3 deliveries, got %d", m.Delivered)
	}

	// unicast to actor 2 → should deliver exactly one
	m2 := newMetrics()
	b2 := newBus(s, f, m2)
	b2.Subscribe(100, 0)
	b2.Subscribe(100, 1)
	b2.Subscribe(100, 2)
	b2.Publish(Envelope{VNI: 100, Type: MsgCommit, Src: 0, Dst: 2})
	if m2.Delivered != 1 {
		t.Fatalf("unicast: expected 1 delivery, got %d", m2.Delivered)
	}
}

// TestBusDropExcludesDelivery verifies that with DropProb=1 no deliver events are
// scheduled; a MsgData drop is a transport drop (DataDropped), not a packet loss.
func TestBusDropExcludesDelivery(t *testing.T) {
	s := NewScheduler(2)
	f := newFaultState(FaultConfig{DropProb: 1, Latency: 1})
	m := newMetrics()
	b := newBus(s, f, m)

	b.Subscribe(200, 0)
	b.Subscribe(200, 1)
	b.Subscribe(200, 2)

	// broadcast a data packet — all should be transport-dropped
	b.Publish(Envelope{VNI: 200, Type: MsgData, Src: 0, Dst: Broadcast})
	if m.Delivered != 0 {
		t.Fatalf("drop=1: expected 0 deliveries, got %d", m.Delivered)
	}
	if m.DataDropped != 2 { // 3 subs - self = 2
		t.Fatalf("drop=1: expected 2 DataDropped, got %d", m.DataDropped)
	}
	if m.CtrlDropped != 0 {
		t.Fatalf("drop=1: data drop should not increment CtrlDropped")
	}

	// ctrl message drop increments CtrlDropped
	b.Publish(Envelope{VNI: 200, Type: MsgCommit, Src: 0, Dst: Broadcast})
	if m.CtrlDropped != 2 {
		t.Fatalf("drop=1: expected 2 CtrlDropped, got %d", m.CtrlDropped)
	}
}

// TestBusPartitionBlocks verifies a partitioned src→dst is not delivered.
func TestBusPartitionBlocks(t *testing.T) {
	s := NewScheduler(3)
	f := newFaultState(FaultConfig{Latency: 1})
	f.applyFault(FaultOp{Kind: faultPartition, On: true,
		SideA: []ActorID{0}, SideB: []ActorID{1}})
	m := newMetrics()
	b := newBus(s, f, m)

	b.Subscribe(300, 0)
	b.Subscribe(300, 1)
	b.Subscribe(300, 2) // actor 2 is unpartitioned

	// broadcast from 0: actor 1 is blocked, actor 2 is not
	b.Publish(Envelope{VNI: 300, Type: MsgCommit, Src: 0, Dst: Broadcast})
	if m.Delivered != 1 {
		t.Fatalf("partition: expected 1 delivered (to actor 2), got %d", m.Delivered)
	}
	if m.Blocked != 1 {
		t.Fatalf("partition: expected 1 blocked, got %d", m.Blocked)
	}
}
