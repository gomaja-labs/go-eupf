package config

import (
	"net"
	"reflect"
	"testing"
)

func TestCloneOwnsEveryReferenceValue(t *testing.T) {
	c := validLimitsConfig()
	value := reflect.ValueOf(&c).Elem()
	for i := range value.NumField() {
		f := value.Field(i)
		if f.CanSet() && f.Type() == reflect.TypeFor[[]string]() {
			f.Set(reflect.ValueOf([]string{"original"}))
		}
	}
	c.Qci2DscpMapping = map[string]int{"1": 10}
	c.n3AdvertisedAddress5G = net.ParseIP("192.0.2.1")
	next := c.Clone()
	nv := reflect.ValueOf(&next).Elem()
	for i := range nv.NumField() {
		f := nv.Field(i)
		if f.CanSet() && f.Type() == reflect.TypeFor[[]string]() {
			f.Index(0).SetString("changed")
			if value.Field(i).Index(0).String() != "original" {
				t.Errorf("clone shares %s", nv.Type().Field(i).Name)
			}
		}
	}
	next.Qci2DscpMapping["1"] = 20
	next.n3AdvertisedAddress5G[0] ^= 0xff
	if c.Qci2DscpMapping["1"] != 10 || c.n3AdvertisedAddress5G.Equal(next.n3AdvertisedAddress5G) {
		t.Fatal("clone shares map or parsed IP")
	}
}
