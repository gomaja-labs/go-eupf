package delivery

import (
	"testing"
)

func TestLoggingCallerRejectsInvalidBoolean(t *testing.T) {
	c := (&CLI{}).newSetLoggingCaller()
	for _, v := range []string{"yes", "tru", "", "FALSE", "0"} {
		if err := c.Args(c, []string{v}); err == nil {
			t.Errorf("accepted invalid boolean %q", v)
		}
	}
	for _, v := range []string{"true", "false"} {
		if err := c.Args(c, []string{v}); err != nil {
			t.Fatal(err)
		}
	}
}
