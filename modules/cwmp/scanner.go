package cwmp

import (
	"context"

	"github.com/zmap/zgrab2"
)

type Flags struct {
	zgrab2.BaseFlags
	Forecast bool `long:"forecast" description:"Enable CWMP heuristics scoring"`
}

func (f *Flags) Help() string    { return "" }
func (f *Flags) Validate(args []string) error { return nil }

type Module struct{}

func (m *Module) NewFlags() any { return new(Flags) }
func (m *Module) NewScanner() zgrab2.Scanner { return new(Scanner) }
func (m *Module) Description() string { return "CWMP scanner (TR-069) with heuristics scoring" }

func init() {
	var module Module
	_, err := zgrab2.AddCommand("cwmp", "CWMP scanner (TR-069)", module.Description(), 7547, &module)
	if err != nil {
		panic(err)
	}
}

type Scanner struct {
	config *Flags
}

func (s *Scanner) Init(flags zgrab2.ScanFlags) error {
	s.config = flags.(*Flags)
	return nil
}
func (s *Scanner) InitPerSender(senderID int) error { return nil }
func (s *Scanner) GetName() string { return s.config.Name }
func (s *Scanner) GetTrigger() string { return s.config.Trigger }
func (s *Scanner) Protocol() string { return "cwmp" }
func (s *Scanner) GetDialerGroupConfig() *zgrab2.DialerGroupConfig {
	return &zgrab2.DialerGroupConfig{
		TransportAgnosticDialerProtocol: zgrab2.TransportTCP,
		BaseFlags: &s.config.BaseFlags,
	}
}

func (s *Scanner) Scan(ctx context.Context, dialer *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	return GetTR069Banner(ctx, dialer, target, s.config)
}
