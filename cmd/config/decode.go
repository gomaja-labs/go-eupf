package config

import (
	"fmt"
	"math"
	"reflect"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

// unmarshalConfiguration retains Viper's string/slice hooks while requiring
// unsigned numeric conversions to preserve their value. Domain bounds are
// checked afterwards by the common configuration validation, before startup.
func unmarshalConfiguration(source *viper.Viper, target any) error {
	return source.UnmarshalExact(target, func(options *mapstructure.DecoderConfig) {
		if options.DecodeHook == nil {
			options.DecodeHook = losslessUnsigned
			return
		}
		options.DecodeHook = mapstructure.ComposeDecodeHookFunc(losslessUnsigned, options.DecodeHook)
	})
}

// Viper enables weak conversion by default, including negative integers and
// booleans to unsigned values. These coercions must not enable release policy
// or change a rule identifier before the application's range checks run.
func losslessUnsigned(from, to reflect.Type, data any) (any, error) {
	if from == nil || to == nil {
		return data, nil
	}
	switch to.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
	default:
		return data, nil
	}
	value := reflect.ValueOf(data)
	invalid := false
	switch value.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		signed := value.Int()
		invalid = signed < 0 || reflect.Zero(to).OverflowUint(uint64(signed))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		invalid = reflect.Zero(to).OverflowUint(value.Uint())
	case reflect.Float32, reflect.Float64:
		number := value.Float()
		invalid = number < 0 || number >= math.Ldexp(1, to.Bits()) || number != math.Trunc(number)
	case reflect.Bool:
		invalid = true
	}
	if invalid {
		return nil, fmt.Errorf("conversion from %s to %s must preserve an unsigned whole number", from, to)
	}
	return data, nil
}
