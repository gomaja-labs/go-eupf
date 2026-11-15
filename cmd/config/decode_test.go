package config

import (
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestUnsignedConfigurationConversionsAreLossless(t *testing.T) {
	for _, value := range []any{int64(-1), uint64(256), float64(1.5), float64(-1), math.NaN(), math.Inf(1), true} {
		if _, err := losslessUnsigned(reflect.TypeOf(value), reflect.TypeFor[uint8](), value); err == nil {
			t.Fatalf("lossy conversion accepted: %v", value)
		}
	}
	for _, value := range []any{int64(255), uint64(255), float64(255), "255"} {
		if _, err := losslessUnsigned(reflect.TypeOf(value), reflect.TypeFor[uint8](), value); err != nil {
			t.Fatalf("exact conversion refused: %v", err)
		}
	}
	for _, value := range []any{math.Exp2(32), math.Exp2(64)} {
		target := reflect.TypeFor[uint32]()
		if value == math.Exp2(64) {
			target = reflect.TypeFor[uint64]()
		}
		if _, err := losslessUnsigned(reflect.TypeOf(value), target, value); err == nil {
			t.Fatal("float overflow accepted")
		}
	}
}

func TestUnsigned64RejectsNegativeSignedInput(t *testing.T) {
	if _, err := losslessUnsigned(reflect.TypeFor[int64](), reflect.TypeFor[uint64](), int64(-1)); err == nil {
		t.Fatal("negative integer wrapped into uint64")
	}
}

func TestConfigurationKeepsCSVAndUnsignedStringInputs(t *testing.T) {
	initConfigFixture(t, "interface_name: lo,n6\ninactivity_release_timeout: '7'\n")
	var c UpfConfig
	if err := c.Unmarshal(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.InterfaceName, []string{"lo", "n6"}) || c.InactivityReleaseTimeout != 7 {
		t.Fatal("string configuration changed")
	}
}

func TestPCCConfigurationRejectsWrappedRuleValues(t *testing.T) {
	old := pccConfigV
	t.Cleanup(func() { pccConfigV = old })
	pccConfigV = viper.New()
	pccConfigV.SetConfigType("yaml")
	if err := pccConfigV.ReadConfig(strings.NewReader("pcc_rules:\n - qer:\n     qfi: 257\n")); err != nil {
		t.Fatal(err)
	}
	var c PCCRulesConfig
	if err := c.Unmarshal(); err == nil {
		t.Fatal("QFI 257 wrapped into QFI 1")
	}
}
