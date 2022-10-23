package aconfig_vault

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/cristalhq/aconfig"
)

type TestConfig struct {
	Str      string `default:"str-def" vault:"secret\\TestPath1\\S1"`
	Bytes    []byte `default:"bytes-def"`
	Int      *int32 `default:"123"`
	HTTPPort int    `default:"8080"  vault:"secret\\TestPath1\\S2"`
	Param    int    // no default tag, so default value
	Sub      SubConfig
	Anon     struct {
		IsAnon bool `default:"true"`
	}

	StrSlice []string       `default:"1,2,3" usage:"just pass strings"`
	Slice    []int          `default:"1,2,3" usage:"just pass elements" vault:"secret\\TestPath2\\S1"`
	Map1     map[string]int `default:"a:1,b:2,c:3"`
	Map2     map[int]string `default:"1:a,2:b,3:c"`

	EmbeddedConfig
}

type EmbeddedConfig struct {
	Em string `default:"em-def" usage:"use... em...field."`
}

type SubConfig struct {
	Float float64 `default:"123.123"`
}

func int32Ptr(a int32) *int32 {
	return &a
}

func failIfErr(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func mustEqual(t testing.TB, got, want interface{}) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("\nhave %+v\nwant %+v", got, want)
	}
}

func Test_OverrideFromVault(t *testing.T) {
	filepath := "test_data/config.json"

	var cfg TestConfig
	loader := aconfig.LoaderFor(&cfg, aconfig.Config{
		SkipDefaults: true,
		SkipEnv:      true,
		SkipFlags:    true,
		Files:        []string{filepath},
	})

	vaultLoader := &VaultLoader{loader}

	failIfErr(t, vaultLoader.Load())

	want := TestConfig{
		Str:      "str-json",
		Bytes:    []byte("Ynl0ZXMtanNvbg=="),
		Int:      int32Ptr(101),
		HTTPPort: 65000,
		Sub: SubConfig{
			Float: 999.111,
		},
		Anon: struct {
			IsAnon bool `default:"true"`
		}{
			IsAnon: true,
		},
	}
	mustEqual(t, cfg, want)

	failIfErr(t, vaultLoader.Override())

	fmt.Printf("%v", cfg)
}
