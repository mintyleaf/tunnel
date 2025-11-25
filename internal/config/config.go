package config

import (
	"flag"
	"fmt"
	"log"
	"os"
	"reflect"
	"strconv"
	"strings"
)

type StringSliceValue struct {
	Target *[]string
}

func NewStringSliceValue(s *[]string) *StringSliceValue {
	return &StringSliceValue{Target: s}
}

func (s *StringSliceValue) String() string {
	if s.Target == nil {
		return ""
	}
	return strings.Join(*s.Target, ",")
}

func (s *StringSliceValue) Set(value string) error {
	*s.Target = append(*s.Target, value)
	return nil
}

func LoadConfig(cfg interface{}) error {
	configValue := reflect.ValueOf(cfg)
	if configValue.Kind() != reflect.Ptr {
		return fmt.Errorf(
			"config must be a pointer to a struct, got %s",
			configValue.Kind(),
		)
	}

	configValue = configValue.Elem()
	if configValue.Kind() != reflect.Struct {
		return fmt.Errorf(
			"config must be a pointer to a struct, got pointer to %s",
			configValue.Kind(),
		)
	}

	configType := configValue.Type()

	for i := 0; i < configType.NumField(); i++ {
		field := configType.Field(i)

		flagName := field.Tag.Get("flag")
		envName := field.Tag.Get("env")
		defaultValue := field.Tag.Get("default")
		usage := field.Tag.Get("usage")

		fieldValue := configValue.Field(i)

		if val, ok := os.LookupEnv(envName); ok {
			switch field.Type.Kind() {
			case reflect.String:
				defaultValue = val
			case reflect.Slice:
				if field.Type.Elem().Kind() == reflect.String {
					if len(val) > 0 {
						stringSlice := strings.Split(val, ",")
						fieldValue.Set(reflect.ValueOf(stringSlice))
					}
				}
			}
		}

		switch field.Type.Kind() {
		case reflect.String:
			defVal := defaultValue

			ptr := fieldValue.Addr().Interface().(*string)
			flag.StringVar(ptr, flagName, defVal, usage)

		case reflect.Bool:
			defVal, err := strconv.ParseBool(defaultValue)
			if err != nil {
				defVal = false
			}

			ptr := fieldValue.Addr().Interface().(*bool)
			flag.BoolVar(ptr, flagName, defVal, usage)
		case reflect.Slice:
			if field.Type.Elem().Kind() == reflect.String {
				slicePtr := fieldValue.Addr().Interface().(*[]string)
				flag.Var(NewStringSliceValue(slicePtr), flagName, usage)
			} else {
				log.Printf(
					"[WARN] unsupported slice element type for flag: %s",
					field.Name,
				)
			}
		default:
			log.Printf(
				"[WARN] unsupported field type for flag: %s",
				field.Name,
			)
		}
	}

	flag.Parse()

	return nil
}
