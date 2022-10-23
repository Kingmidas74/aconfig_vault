package aconfig_vault

import (
	"context"
	"fmt"
	"log"
	"reflect"
	"strings"
	"unsafe"

	"github.com/cristalhq/aconfig"
	vault "github.com/hashicorp/vault/api"
)

type VaultLoader struct {
	*aconfig.Loader
}

func (l *VaultLoader) Override() error {

	config := vault.DefaultConfig()
	config.Address = "http://127.0.0.1:8200"

	client, err := vault.NewClient(config)
	if err != nil {
		log.Fatalf("Unable to initialize a Vault client: %v", err)
	}

	client.SetToken("myroot")

	ctx := context.Background()

	l2 := l
	l.WalkFields(func(f aconfig.Field) bool {

		vaultPath := f.Tag("vault")
		if vaultPath != "" {
			fmt.Printf("%v", f)

			vaultPaths := strings.Split(vaultPath, "\\")

			secret, err := client.KVv2(vaultPaths[0]).Get(ctx, vaultPaths[1])
			if err != nil {
				log.Fatalf(
					"Unable to read the super secret password from the vault: %v",
					err,
				)
			}

			value, ok := secret.Data[vaultPaths[2]].(string)
			if !ok {
				log.Fatalf(
					"value type assertion failed: %T %#v",
					secret.Data[vaultPaths[2]],
					secret.Data[vaultPaths[2]],
				)
			}

			log.Printf("Super secret password [%s] was retrieved.\n", value)

			val := reflect.ValueOf(value)

			rf := reflect.ValueOf(f).Elem().FieldByName("value")
			reflect.NewAt(rf.Type(), unsafe.Pointer(rf.UnsafeAddr())).
				Elem().
				Set(reflect.ValueOf(val))

			a := reflect.ValueOf(f).Elem().FieldByName("value").String()
			log.Printf("%v %v %v \n", f, a, l2)

		}
		return true
	})
	return nil
}

func GetUnexportedField(field reflect.Value) reflect.Value {
	return reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()
}

func SetUnexportedField(field reflect.Value, value interface{}) {

}

/*
func (l *VaultLoader) setFieldData(field *fieldData, value interface{}) error {
	// unwrap pointers
	for field.value.Type().Kind() == reflect.Ptr {
		if field.value.IsNil() {
			field.value.Set(reflect.New(field.value.Type().Elem()))
		}
		field.value = field.value.Elem()
	}

	if value == "" {
		return nil
	}

	pv := field.value.Addr().Interface()
	if v, ok := pv.(encoding.TextUnmarshaler); ok {
		return v.UnmarshalText([]byte(fmt.Sprint(value)))
	}

	switch kind := field.value.Type().Kind(); kind {
	case reflect.Bool:
		return l.setBool(field, fmt.Sprint(value))

	case reflect.String:
		return l.setString(field, fmt.Sprint(value))

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32:
		return l.setInt(field, fmt.Sprint(value))

	case reflect.Int64:
		return l.setInt64(field, fmt.Sprint(value))

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return l.setUint(field, fmt.Sprint(value))

	case reflect.Float32, reflect.Float64:
		return l.setFloat(field, fmt.Sprint(value))

	case reflect.Interface:
		return l.setInterface(field, value)

	case reflect.Slice:
		if field.field.Type.Elem().Kind() == reflect.Struct {
			if value == nil {
				return nil
			}
			v, ok := value.([]interface{})
			if !ok {
				panic(fmt.Errorf("%T %v", value, value))
			}

			slice := reflect.MakeSlice(field.field.Type, len(v), len(v))
			for i, val := range v {
				vv := mii(val)

				fd := l.newFieldData(reflect.StructField{}, slice.Index(i), nil)
				if err := l.m2s(vv, fd.value); err != nil {
					return err
				}
			}
			field.value.Set(slice)
			return nil
		}
		return l.setSlice(field, sliceToString(value))

	case reflect.Map:
		v, ok := value.(map[string]interface{})
		if !ok {
			return l.setMap(field, fmt.Sprint(value))
		}

		mapp := reflect.MakeMapWithSize(field.field.Type, len(v))
		for key, val := range v {
			fdk := l.newSimpleFieldData(reflect.New(field.field.Type.Key()).Elem())
			if err := l.setFieldData(fdk, key); err != nil {
				return fmt.Errorf("incorrect map key %q: %w", key, err)
			}

			fdv := l.newSimpleFieldData(reflect.New(field.field.Type.Elem()).Elem())
			if err := l.setFieldData(fdv, val); err != nil {
				return fmt.Errorf("incorrect map value %q: %w", val, err)
			}
			mapp.SetMapIndex(fdk.value, fdv.value)
		}
		field.value.Set(mapp)
		return nil

	default:
		return fmt.Errorf("type kind %q isn't supported", kind)
	}
}

func (*VaultLoader) setBool(field *fieldData, value string) error {
	val, err := strconv.ParseBool(value)
	if err != nil {
		return err
	}
	field.value.SetBool(val)
	return nil
}

func (*VaultLoader) setInt(field *fieldData, value string) error {
	val, err := strconv.ParseInt(value, 0, field.value.Type().Bits())
	if err != nil {
		return err
	}
	field.value.SetInt(val)
	return nil
}

func (l *VaultLoader) setInt64(field *fieldData, value string) error {
	if field.field.Type == reflect.TypeOf(time.Second) {
		val, err := time.ParseDuration(value)
		if err != nil {
			return err
		}
		field.value.Set(reflect.ValueOf(val))
		return nil
	}
	return l.setInt(field, value)
}

func (*VaultLoader) setUint(field *fieldData, value string) error {
	val, err := strconv.ParseUint(value, 0, field.value.Type().Bits())
	if err != nil {
		return err
	}
	field.value.SetUint(val)
	return nil
}

func (*VaultLoader) setFloat(field *fieldData, value string) error {
	val, err := strconv.ParseFloat(value, field.value.Type().Bits())
	if err != nil {
		return err
	}
	field.value.SetFloat(val)
	return nil
}

func (*VaultLoader) setString(field *fieldData, value string) error {
	field.value.SetString(value)
	return nil
}

func (*VaultLoader) setInterface(field *fieldData, value interface{}) error {
	field.value.Set(reflect.ValueOf(value))
	return nil
}

func (l *VaultLoader) setSlice(field *fieldData, value string) error {
	// Special case for []byte
	if field.field.Type.Elem().Kind() == reflect.Uint8 {
		value := reflect.ValueOf([]byte(value))
		field.value.Set(value)
		return nil
	}

	vals := strings.Split(value, ",")
	slice := reflect.MakeSlice(field.field.Type, len(vals), len(vals))
	for i, val := range vals {
		val = strings.TrimSpace(val)

		fd := l.newFieldData(reflect.StructField{}, slice.Index(i), nil)
		if err := l.setFieldData(fd, val); err != nil {
			return fmt.Errorf("incorrect slice item %q: %w", val, err)
		}
	}
	field.value.Set(slice)
	return nil
}

func (l *VaultLoader) setMap(field *fieldData, value string) error {
	vals := strings.Split(value, ",")
	mapField := reflect.MakeMapWithSize(field.field.Type, len(vals))

	for _, val := range vals {
		entry := strings.SplitN(val, ":", 2)
		if len(entry) != 2 {
			return fmt.Errorf("incorrect map item: %s", val)
		}
		key := strings.TrimSpace(entry[0])
		val := strings.TrimSpace(entry[1])

		fdk := l.newSimpleFieldData(reflect.New(field.field.Type.Key()).Elem())
		if err := l.setFieldData(fdk, key); err != nil {
			return fmt.Errorf("incorrect map key %q: %w", key, err)
		}

		fdv := l.newSimpleFieldData(reflect.New(field.field.Type.Elem()).Elem())
		fdv.field.Type = field.field.Type.Elem()
		if err := l.setFieldData(fdv, val); err != nil {
			return fmt.Errorf("incorrect map value %q: %w", val, err)
		}
		mapField.SetMapIndex(fdk.value, fdv.value)
	}
	field.value.Set(mapField)
	return nil
}
*/
