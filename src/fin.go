package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/liuylv/trojan-prober/src/log"
)

// finSession holds per-probe FIN capture state.
type finSession struct {
	mu          sync.Mutex
	startTime   time.Time
	finTime     time.Time
	finDuration time.Duration
	captured    bool
	err         error
}

func (s *finSession) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.startTime = time.Time{}
	s.finTime = time.Time{}
	s.finDuration = 0
	s.captured = false
	s.err = nil
}

func (s *finSession) waitForFIN(timeout time.Duration) (time.Time, time.Duration, bool, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		if s.err != nil {
			err := s.err
			s.mu.Unlock()
			return time.Time{}, 0, false, err
		}
		if s.captured {
			ft := s.finTime
			fd := s.finDuration
			s.mu.Unlock()
			return ft, fd, true, nil
		}
		s.mu.Unlock()
		time.Sleep(100 * time.Millisecond)
	}
	return time.Time{}, 0, false, nil
}

func startFINCapture(ctx context.Context, cfg Config, session *finSession, targetHost string, targetPort uint16) {
	session.reset()
	go func() {
		err := captureFIN(ctx, cfg, session, targetHost, targetPort)
		if err != nil {
			session.mu.Lock()
			session.err = err
			session.mu.Unlock()
			log.Debug("FIN capture ended: %v", err)
		}
	}()
}

func captureFIN(ctx context.Context, cfg Config, session *finSession, targetIP string, targetPort uint16) error {
	handle, err := pcap.OpenLive("any", 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("pcap open: %w", err)
	}
	defer handle.Close()

	filter := fmt.Sprintf("tcp and src host %s and src port %d", targetIP, targetPort)
	if err := handle.SetBPFFilter(filter); err != nil {
		return fmt.Errorf("bpf filter: %w", err)
	}

	session.mu.Lock()
	session.startTime = time.Now()
	session.mu.Unlock()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		select {
		case packet, ok := <-packetSource.Packets():
			if !ok {
				return fmt.Errorf("packet source closed")
			}
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				if tcp.FIN {
					now := time.Now()
					session.mu.Lock()
					session.finTime = now
					session.finDuration = now.Sub(session.startTime)
					session.captured = true
					fd := session.finDuration
					session.mu.Unlock()
					log.Info("Capture FIN packet at: %s", fd)
					return nil
				}
			}
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}
