package tls

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// oldProfileCiphers is the Old profile cipher list from
// configv1.TLSProfiles pruned to runtime-supported suites at TLS 1.0
// (TLS 1.3-only names excluded).
var oldProfileCiphers = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
}

var tls13OnlyCiphers = []uint16{
	tls.TLS_AES_128_GCM_SHA256,
	tls.TLS_AES_256_GCM_SHA384,
	tls.TLS_CHACHA20_POLY1305_SHA256,
}

func TestShouldHonorClusterTLSProfile(t *testing.T) {
	tests := []struct {
		name      string
		adherence configv1.TLSAdherencePolicy
		want      bool
	}{
		{"empty adheres to NoOpinion", "", false},
		{"NoOpinion", configv1.TLSAdherencePolicyNoOpinion, false},
		{"LegacyAdheringComponentsOnly", configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly, false},
		{"StrictAllComponents", configv1.TLSAdherencePolicyStrictAllComponents, true},
		{"unknown value fails secure", "Bananas", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldHonorClusterTLSProfile(tt.adherence); got != tt.want {
				t.Errorf("shouldHonorClusterTLSProfile(%q) = %v, want %v", tt.adherence, got, tt.want)
			}
		})
	}
}

func TestParseProfile(t *testing.T) {
	tests := []struct {
		profile        *configv1.TLSSecurityProfile
		adherence      configv1.TLSAdherencePolicy
		name           string
		wantCiphers    []uint16
		wantMinVersion uint16
		wantErr        bool
	}{
		{
			name:           "nil profile returns Intermediate defaults",
			adherence:      configv1.TLSAdherencePolicyStrictAllComponents,
			profile:        nil,
			wantMinVersion: tls.VersionTLS12,
			wantCiphers:    intermediateCiphers,
		},
		{
			name:           "empty profile returns Intermediate defaults",
			adherence:      configv1.TLSAdherencePolicyStrictAllComponents,
			profile:        &configv1.TLSSecurityProfile{},
			wantMinVersion: tls.VersionTLS12,
			wantCiphers:    intermediateCiphers,
		},
		{
			name:      "Intermediate type",
			adherence: configv1.TLSAdherencePolicyStrictAllComponents,
			profile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileIntermediateType,
			},
			wantMinVersion: tls.VersionTLS12,
			wantCiphers:    intermediateCiphers,
		},
		{
			name:      "Modern returns TLS 1.3 with TLS 1.3 suites",
			adherence: configv1.TLSAdherencePolicyStrictAllComponents,
			profile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileModernType,
			},
			wantMinVersion: tls.VersionTLS13,
			wantCiphers:    tls13OnlyCiphers,
		},
		{
			name:      "Old maps to TLS 1.0 with runtime-supported suites",
			adherence: configv1.TLSAdherencePolicyStrictAllComponents,
			profile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileOldType,
			},
			wantMinVersion: tls.VersionTLS10,
			wantCiphers:    oldProfileCiphers,
		},
		{
			name:           "Modern ignored under NoOpinion adherence, Intermediate used",
			adherence:      configv1.TLSAdherencePolicyNoOpinion,
			profile:        &configv1.TLSSecurityProfile{Type: configv1.TLSProfileModernType},
			wantMinVersion: tls.VersionTLS12,
			wantCiphers:    intermediateCiphers,
		},
		{
			name:           "Modern ignored under LegacyAdheringComponentsOnly adherence, Intermediate used",
			adherence:      configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly,
			profile:        &configv1.TLSSecurityProfile{Type: configv1.TLSProfileModernType},
			wantMinVersion: tls.VersionTLS12,
			wantCiphers:    intermediateCiphers,
		},
		{
			name:           "unknown adherence treated as strict",
			adherence:      "MaybeSecure",
			profile:        &configv1.TLSSecurityProfile{Type: configv1.TLSProfileModernType},
			wantMinVersion: tls.VersionTLS13,
			wantCiphers:    tls13OnlyCiphers,
		},
		{
			name:      "Custom with valid ciphers",
			adherence: configv1.TLSAdherencePolicyStrictAllComponents,
			profile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						MinTLSVersion: "VersionTLS12",
						Ciphers:       []string{"ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-RSA-AES256-GCM-SHA384"},
					},
				},
			},
			wantMinVersion: tls.VersionTLS12,
			wantCiphers:    []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
		},
		{
			name:      "Custom with unsupported cipher skips it",
			adherence: configv1.TLSAdherencePolicyStrictAllComponents,
			profile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						MinTLSVersion: "VersionTLS12",
						Ciphers:       []string{"ECDHE-ECDSA-AES128-GCM-SHA256", "UNSUPPORTED-CIPHER"},
					},
				},
			},
			wantMinVersion: tls.VersionTLS12,
			wantCiphers:    []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		},
		{
			name:      "Custom with all unsupported ciphers errors",
			adherence: configv1.TLSAdherencePolicyStrictAllComponents,
			profile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						MinTLSVersion: "VersionTLS12",
						Ciphers:       []string{"DHE-RSA-AES128-GCM-SHA256"},
					},
				},
			},
			wantErr: true,
		},
		{
			name:      "Custom with whitespace-padded cipher names still resolves",
			adherence: configv1.TLSAdherencePolicyStrictAllComponents,
			profile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						MinTLSVersion: "VersionTLS12",
						Ciphers:       []string{"  ECDHE-ECDSA-AES128-GCM-SHA256  ", " ECDHE-RSA-AES256-GCM-SHA384"},
					},
				},
			},
			wantMinVersion: tls.VersionTLS12,
			wantCiphers:    []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
		},
		{
			name:      "Custom with whitespace-only cipher entries are skipped",
			adherence: configv1.TLSAdherencePolicyStrictAllComponents,
			profile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						MinTLSVersion: "VersionTLS12",
						Ciphers:       []string{"   ", "ECDHE-ECDSA-AES128-GCM-SHA256", "  "},
					},
				},
			},
			wantMinVersion: tls.VersionTLS12,
			wantCiphers:    []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		},
		{
			name:      "Custom with nil custom block errors under strict adherence",
			adherence: configv1.TLSAdherencePolicyStrictAllComponents,
			profile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
			},
			wantErr: true,
		},
		{
			name:           "Custom with nil custom block uses Intermediate under NoOpinion adherence",
			adherence:      configv1.TLSAdherencePolicyNoOpinion,
			profile:        &configv1.TLSSecurityProfile{Type: configv1.TLSProfileCustomType},
			wantMinVersion: tls.VersionTLS12,
			wantCiphers:    intermediateCiphers,
		},
		{
			name:      "Custom minTLSVersion VersionTLS10 is honored exactly",
			adherence: configv1.TLSAdherencePolicyStrictAllComponents,
			profile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						MinTLSVersion: "VersionTLS10",
						Ciphers:       []string{"ECDHE-RSA-AES128-GCM-SHA256"},
					},
				},
			},
			wantMinVersion: tls.VersionTLS10,
			wantCiphers:    []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		},
		{
			name:      "Custom minTLSVersion VersionTLS11 is honored exactly",
			adherence: configv1.TLSAdherencePolicyStrictAllComponents,
			profile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						MinTLSVersion: "VersionTLS11",
					},
				},
			},
			wantMinVersion: tls.VersionTLS11,
			wantCiphers:    nil,
		},
		{
			name:      "Custom with OpenSSL alias AES256-GCM-SHA384 maps to the RSA suite",
			adherence: configv1.TLSAdherencePolicyStrictAllComponents,
			profile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						MinTLSVersion: "VersionTLS12",
						Ciphers:       []string{"AES256-GCM-SHA384"},
					},
				},
			},
			wantMinVersion: tls.VersionTLS12,
			wantCiphers:    []uint16{tls.TLS_RSA_WITH_AES_256_GCM_SHA384},
		},
		{
			name:      "Custom with OpenSSL alias DES-CBC3-SHA maps to the 3DES suite",
			adherence: configv1.TLSAdherencePolicyStrictAllComponents,
			profile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						MinTLSVersion: "VersionTLS12",
						Ciphers:       []string{"DES-CBC3-SHA"},
					},
				},
			},
			wantMinVersion: tls.VersionTLS12,
			wantCiphers:    []uint16{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA},
		},
		{
			name:      "Custom with only TLS 1.3 cipher names and min TLS 1.2 errors",
			adherence: configv1.TLSAdherencePolicyStrictAllComponents,
			profile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						MinTLSVersion: "VersionTLS12",
						Ciphers:       []string{"TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"},
					},
				},
			},
			wantErr: true,
		},
		{
			name:      "Custom with unknown minTLSVersion errors under strict adherence",
			adherence: configv1.TLSAdherencePolicyStrictAllComponents,
			profile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						MinTLSVersion: "VersionTLS14",
					},
				},
			},
			wantErr: true,
		},
		{
			name:      "Custom with empty minTLSVersion errors under strict adherence",
			adherence: configv1.TLSAdherencePolicyStrictAllComponents,
			profile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						Ciphers: []string{"ECDHE-RSA-AES128-GCM-SHA256"},
					},
				},
			},
			wantErr: true,
		},
		{
			name:      "Custom with unknown minTLSVersion uses Intermediate under NoOpinion adherence",
			adherence: configv1.TLSAdherencePolicyNoOpinion,
			profile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						MinTLSVersion: "VersionTLS14",
					},
				},
			},
			wantMinVersion: tls.VersionTLS12,
			wantCiphers:    intermediateCiphers,
		},
		{
			name:      "Custom TLS 1.3 keeps ciphers informational without restriction",
			adherence: configv1.TLSAdherencePolicyStrictAllComponents,
			profile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						MinTLSVersion: "VersionTLS13",
						Ciphers:       []string{"ECDHE-RSA-AES128-GCM-SHA256"},
					},
				},
			},
			wantMinVersion: tls.VersionTLS13,
			wantCiphers:    []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		},
		{
			name:      "Custom without ciphers has no suite restriction",
			adherence: configv1.TLSAdherencePolicyStrictAllComponents,
			profile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						MinTLSVersion: "VersionTLS12",
					},
				},
			},
			wantMinVersion: tls.VersionTLS12,
			wantCiphers:    nil,
		},
		{
			name:      "unknown type errors under strict adherence",
			adherence: configv1.TLSAdherencePolicyStrictAllComponents,
			profile: &configv1.TLSSecurityProfile{
				Type: "SuperSecure",
			},
			wantErr: true,
		},
		{
			name:           "unknown type uses Intermediate under NoOpinion adherence",
			adherence:      configv1.TLSAdherencePolicyNoOpinion,
			profile:        &configv1.TLSSecurityProfile{Type: "SuperSecure"},
			wantMinVersion: tls.VersionTLS12,
			wantCiphers:    intermediateCiphers,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMinVersion, gotCiphers, err := parseProfile(tt.profile, tt.adherence)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected err but got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if gotMinVersion != tt.wantMinVersion {
				t.Errorf("parseProfile() minVersion = %d, want %d", gotMinVersion, tt.wantMinVersion)
			}

			if tt.wantCiphers == nil {
				if gotCiphers != nil {
					t.Errorf("parseProfile() ciphers = %v, want nil", gotCiphers)
				}
				return
			}

			if gotCiphers == nil {
				t.Fatal("expected non-nil empty slice, got nil")
			}
			if len(gotCiphers) != len(tt.wantCiphers) {
				t.Errorf("parseProfile() ciphers length = %d, want %d", len(gotCiphers), len(tt.wantCiphers))
				return
			}
			for i, c := range gotCiphers {
				if c != tt.wantCiphers[i] {
					t.Errorf("parseProfile() ciphers[%d] = %d, want %d", i, c, tt.wantCiphers[i])
				}
			}
		})
	}
}

func testScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = configv1.Install(s)
	return s
}

func TestResolve(t *testing.T) {
	tests := []struct {
		name               string
		objects            []runtime.Object
		wantErr            bool
		wantProfileFetched bool
		wantMinVersion     uint16
		wantCiphers        []uint16
	}{
		{
			name:               "APIServer not found falls back to Intermediate",
			wantProfileFetched: false,
			wantMinVersion:     tls.VersionTLS12,
			wantCiphers:        intermediateCiphers,
		},
		{
			name: "APIServer with Old profile under strict adherence honors TLS 1.0",
			objects: []runtime.Object{
				&configv1.APIServer{
					ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
					Spec: configv1.APIServerSpec{
						TLSAdherence:       configv1.TLSAdherencePolicyStrictAllComponents,
						TLSSecurityProfile: &configv1.TLSSecurityProfile{Type: configv1.TLSProfileOldType},
					},
				},
			},
			wantProfileFetched: true,
			wantMinVersion:     tls.VersionTLS10,
			wantCiphers:        oldProfileCiphers,
		},
		{
			name: "APIServer with Custom minTLSVersion VersionTLS11 honored exactly",
			objects: []runtime.Object{
				&configv1.APIServer{
					ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
					Spec: configv1.APIServerSpec{
						TLSAdherence: configv1.TLSAdherencePolicyStrictAllComponents,
						TLSSecurityProfile: &configv1.TLSSecurityProfile{
							Type: configv1.TLSProfileCustomType,
							Custom: &configv1.CustomTLSProfile{
								TLSProfileSpec: configv1.TLSProfileSpec{
									MinTLSVersion: "VersionTLS11",
								},
							},
						},
					},
				},
			},
			wantProfileFetched: true,
			wantMinVersion:     tls.VersionTLS11,
			wantCiphers:        nil,
		},
		{
			name: "APIServer with Modern profile",
			objects: []runtime.Object{
				&configv1.APIServer{
					ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
					Spec: configv1.APIServerSpec{
						TLSAdherence: configv1.TLSAdherencePolicyStrictAllComponents,
						TLSSecurityProfile: &configv1.TLSSecurityProfile{
							Type: configv1.TLSProfileModernType,
						},
					},
				},
			},
			wantProfileFetched: true,
			wantMinVersion:     tls.VersionTLS13,
			wantCiphers:        nil,
		},
		{
			name: "APIServer with Modern profile and NoOpinion adherence uses Intermediate",
			objects: []runtime.Object{
				&configv1.APIServer{
					ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
					Spec: configv1.APIServerSpec{
						TLSAdherence: configv1.TLSAdherencePolicyNoOpinion,
						TLSSecurityProfile: &configv1.TLSSecurityProfile{
							Type: configv1.TLSProfileModernType,
						},
					},
				},
			},
			wantProfileFetched: true,
			wantMinVersion:     tls.VersionTLS12,
			wantCiphers:        intermediateCiphers,
		},
		{
			name: "APIServer with Custom profile of all unsupported ciphers errors under strict adherence",
			objects: []runtime.Object{
				&configv1.APIServer{
					ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
					Spec: configv1.APIServerSpec{
						TLSAdherence: configv1.TLSAdherencePolicyStrictAllComponents,
						TLSSecurityProfile: &configv1.TLSSecurityProfile{
							Type: configv1.TLSProfileCustomType,
							Custom: &configv1.CustomTLSProfile{
								TLSProfileSpec: configv1.TLSProfileSpec{
									MinTLSVersion: "VersionTLS12",
									Ciphers:       []string{"UNSUPPORTED-CIPHER-1", "UNSUPPORTED-CIPHER-2"},
								},
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "APIServer with Custom profile of all unsupported ciphers uses Intermediate under NoOpinion adherence",
			objects: []runtime.Object{
				&configv1.APIServer{
					ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
					Spec: configv1.APIServerSpec{
						TLSAdherence: configv1.TLSAdherencePolicyNoOpinion,
						TLSSecurityProfile: &configv1.TLSSecurityProfile{
							Type: configv1.TLSProfileCustomType,
							Custom: &configv1.CustomTLSProfile{
								TLSProfileSpec: configv1.TLSProfileSpec{
									MinTLSVersion: "VersionTLS12",
									Ciphers:       []string{"UNSUPPORTED-CIPHER-1", "UNSUPPORTED-CIPHER-2"},
								},
							},
						},
					},
				},
			},
			wantProfileFetched: true,
			wantMinVersion:     tls.VersionTLS12,
			wantCiphers:        intermediateCiphers,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := testScheme()
			builder := fake.NewClientBuilder().WithScheme(s)
			for _, obj := range tt.objects {
				builder = builder.WithRuntimeObjects(obj)
			}
			c := builder.Build()

			result, err := resolveWithClient(context.Background(), c)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Resolve() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if result.ProfileFetched != tt.wantProfileFetched {
				t.Errorf("ProfileFetched = %v, want %v", result.ProfileFetched, tt.wantProfileFetched)
			}
			if len(result.TLSOpts) == 0 {
				t.Error("TLSOpts should not be empty")
			}
			// Start from deliberately wrong values so the callbacks must
			// actually write them.
			cfg := &tls.Config{
				MinVersion:   tls.VersionTLS12,
				CipherSuites: []uint16{tls.TLS_RSA_WITH_RC4_128_SHA},
			}
			if tt.wantMinVersion != tls.VersionTLS13 {
				cfg.MinVersion = tls.VersionTLS13
			}
			for _, fn := range result.TLSOpts {
				fn(cfg)
			}
			if len(cfg.NextProtos) == 0 {
				t.Error("NextProtos should be set")
			}
			if cfg.MinVersion != tt.wantMinVersion {
				t.Errorf("MinVersion = %d, want %d", cfg.MinVersion, tt.wantMinVersion)
			}
			if tt.wantCiphers == nil {
				// The sentinel proves the callbacks did not set CipherSuites.
				if !reflect.DeepEqual(cfg.CipherSuites, []uint16{tls.TLS_RSA_WITH_RC4_128_SHA}) {
					t.Errorf("CipherSuites must not be set, got %v", cfg.CipherSuites)
				}
			} else if !reflect.DeepEqual(cfg.CipherSuites, tt.wantCiphers) {
				t.Errorf("CipherSuites = %v, want %v", cfg.CipherSuites, tt.wantCiphers)
			}
		})
	}
}

// TestResolve_OldProfileAppliedToConfig verifies the Old profile end to end
// on a tls.Config: exact TLS 1.0 minimum and pruned runtime-supported suites.
func TestResolve_OldProfileAppliedToConfig(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme()).WithRuntimeObjects(
		&configv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
			Spec: configv1.APIServerSpec{
				TLSAdherence:       configv1.TLSAdherencePolicyStrictAllComponents,
				TLSSecurityProfile: &configv1.TLSSecurityProfile{Type: configv1.TLSProfileOldType},
			},
		},
	).Build()

	result, err := resolveWithClient(context.Background(), c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cfg := &tls.Config{}
	for _, fn := range result.TLSOpts {
		fn(cfg)
	}

	if cfg.MinVersion != tls.VersionTLS10 {
		t.Errorf("MinVersion = %#04x, want TLS 1.0", cfg.MinVersion)
	}
	if len(cfg.CipherSuites) == 0 {
		t.Fatal("CipherSuites should be non-empty for the Old profile")
	}
	if !slices.Contains(cfg.CipherSuites, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) {
		t.Errorf("CipherSuites should contain TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, got %v", cfg.CipherSuites)
	}
	for _, id := range cfg.CipherSuites {
		if isTLS13CipherID(id) {
			t.Errorf("CipherSuites must not contain TLS 1.3-only suite %#04x for the Old profile", id)
		}
	}
	if len(cfg.NextProtos) == 0 {
		t.Error("NextProtos should be set")
	}
}

type errorClient struct {
	client.Client
	err error
}

func (c *errorClient) Get(_ context.Context, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
	return c.err
}

func TestResolve_FetchLadder(t *testing.T) {
	apiservers := schema.GroupResource{Group: "config.openshift.io", Resource: "apiservers"}
	tests := []struct {
		name            string
		err             error
		wantErr         bool
		wantErrContains string
		wantFetched     bool
	}{
		{
			name:        "NoMatchError falls back to Intermediate without watcher",
			err:         &meta.NoResourceMatchError{PartialResource: schema.GroupVersionResource{Group: "config.openshift.io", Resource: "apiservers", Version: "v1"}},
			wantFetched: false,
		},
		{
			name:        "NotFound falls back to Intermediate without watcher",
			err:         apierrors.NewNotFound(apiservers, "cluster"),
			wantFetched: false,
		},
		{
			name:        "ServiceUnavailable falls back to Intermediate with watcher",
			err:         apierrors.NewServiceUnavailable("API unavailable"),
			wantFetched: true,
		},
		{
			name:        "Timeout falls back to Intermediate with watcher",
			err:         apierrors.NewTimeoutError("timeout", 1),
			wantFetched: true,
		},
		{
			name:        "ServerTimeout falls back to Intermediate with watcher",
			err:         apierrors.NewServerTimeout(apiservers, "get", 1),
			wantFetched: true,
		},
		{
			name:        "TooManyRequests falls back to Intermediate with watcher",
			err:         apierrors.NewTooManyRequests("slow down", 1),
			wantFetched: true,
		},
		{
			name:        "DeadlineExceeded falls back to Intermediate with watcher",
			err:         fmt.Errorf("get apiservers: %w", context.DeadlineExceeded),
			wantFetched: true,
		},
		{
			name:            "Forbidden fails closed with RBAC hint",
			err:             apierrors.NewForbidden(apiservers, "cluster", nil),
			wantErr:         true,
			wantErrContains: "RBAC",
		},
		{
			name:    "Unauthorized fails closed",
			err:     apierrors.NewUnauthorized("unauthenticated"),
			wantErr: true,
		},
		{
			name:    "other errors fail closed",
			err:     errors.New("boom"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := resolveWithClient(context.Background(), &errorClient{err: tt.err})
			if (err != nil) != tt.wantErr {
				t.Fatalf("resolveWithClient() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				if tt.wantErrContains != "" && !strings.Contains(err.Error(), tt.wantErrContains) {
					t.Errorf("error %q should contain %q", err.Error(), tt.wantErrContains)
				}
				return
			}
			if result.ProfileFetched != tt.wantFetched {
				t.Errorf("ProfileFetched = %v, want %v", result.ProfileFetched, tt.wantFetched)
			}
			if tt.wantFetched {
				if result.Profile == nil || result.Profile.Type != configv1.TLSProfileIntermediateType {
					t.Errorf("Profile should be seeded with Intermediate on transient errors, got %v", result.Profile)
				}
			}
			cfg := &tls.Config{MinVersion: tls.VersionTLS13, CipherSuites: []uint16{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA}}
			for _, fn := range result.TLSOpts {
				fn(cfg)
			}
			if cfg.MinVersion != tls.VersionTLS12 {
				t.Errorf("MinVersion = %d, want Intermediate floor %d", cfg.MinVersion, tls.VersionTLS12)
			}
			if !reflect.DeepEqual(cfg.CipherSuites, intermediateCiphers) {
				t.Errorf("CipherSuites = %v, want Intermediate suites %v", cfg.CipherSuites, intermediateCiphers)
			}
			if len(cfg.NextProtos) == 0 {
				t.Error("NextProtos should be set")
			}
		})
	}
}

func TestResolve_TransientError(t *testing.T) {
	err := apierrors.NewServiceUnavailable("API unavailable")
	c := &errorClient{err: err}

	result, resolveErr := resolveWithClient(context.Background(), c)
	if resolveErr != nil {
		t.Fatalf("expected no error on transient failure, got %v", resolveErr)
	}
	if !result.ProfileFetched {
		t.Error("ProfileFetched should be true on transient errors (watcher self-healing)")
	}
	if result.Profile == nil {
		t.Fatal("Profile should be non-nil on transient errors (seeded with Intermediate for watcher comparison)")
	}
	if result.Profile.Type != configv1.TLSProfileIntermediateType {
		t.Errorf("Profile.Type = %v, want Intermediate", result.Profile.Type)
	}
}

func TestResolve_FatalError(t *testing.T) {
	err := apierrors.NewForbidden(
		schema.GroupResource{Group: "config.openshift.io", Resource: "apiservers"},
		"cluster", nil,
	)
	c := &errorClient{err: err}

	_, resolveErr := resolveWithClient(context.Background(), c)
	if resolveErr == nil {
		t.Fatal("expected error on Forbidden, got nil")
	}
}

func TestResolve_CustomAllUnsupportedCiphers(t *testing.T) {
	s := testScheme()
	c := fake.NewClientBuilder().WithScheme(s).WithRuntimeObjects(
		&configv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
			Spec: configv1.APIServerSpec{
				TLSAdherence: configv1.TLSAdherencePolicyStrictAllComponents,
				TLSSecurityProfile: &configv1.TLSSecurityProfile{
					Type: configv1.TLSProfileCustomType,
					Custom: &configv1.CustomTLSProfile{
						TLSProfileSpec: configv1.TLSProfileSpec{
							MinTLSVersion: "VersionTLS12",
							Ciphers:       []string{"UNSUPPORTED-CIPHER-1", "UNSUPPORTED-CIPHER-2"},
						},
					},
				},
			},
		},
	).Build()

	_, err := resolveWithClient(context.Background(), c)
	if err == nil {
		t.Fatal("expected error when all ciphers are unsupported, got nil")
	}
}

func TestProfileWatcher_AdherenceChange(t *testing.T) {
	profile := &configv1.TLSSecurityProfile{Type: configv1.TLSProfileIntermediateType}
	tests := []struct {
		name             string
		initialAdherence configv1.TLSAdherencePolicy
		currentAdherence configv1.TLSAdherencePolicy
		wantCancel       bool
	}{
		{"NoOpinion unchanged", configv1.TLSAdherencePolicyNoOpinion, configv1.TLSAdherencePolicyNoOpinion, false},
		{"Strict unchanged", configv1.TLSAdherencePolicyStrictAllComponents, configv1.TLSAdherencePolicyStrictAllComponents, false},
		{"Legacy equals NoOpinion for the gate", configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly, configv1.TLSAdherencePolicyNoOpinion, false},
		{"NoOpinion flips to Strict", configv1.TLSAdherencePolicyNoOpinion, configv1.TLSAdherencePolicyStrictAllComponents, true},
		{"Strict flips to NoOpinion", configv1.TLSAdherencePolicyStrictAllComponents, configv1.TLSAdherencePolicyNoOpinion, true},
		{"NoOpinion flips to unknown (treated as Strict)", configv1.TLSAdherencePolicyNoOpinion, "Weird", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := fake.NewClientBuilder().WithScheme(testScheme()).WithRuntimeObjects(
				&configv1.APIServer{
					ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
					Spec: configv1.APIServerSpec{
						TLSAdherence:       tt.currentAdherence,
						TLSSecurityProfile: profile,
					},
				},
			).Build()

			ctx, cancel := context.WithCancel(context.Background())
			w := &profileWatcher{
				client:           c,
				cancel:           cancel,
				initialProfile:   profile,
				initialAdherence: tt.initialAdherence,
			}
			if _, err := w.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "cluster"}}); err != nil {
				t.Fatalf("unexpected reconcile error: %v", err)
			}

			canceled := false
			select {
			case <-ctx.Done():
				canceled = true
			default:
			}
			if canceled != tt.wantCancel {
				t.Errorf("cancel fired = %v, want %v", canceled, tt.wantCancel)
			}
		})
	}
}

func TestProfileEqual(t *testing.T) {
	tests := []struct {
		name string
		a, b *configv1.TLSSecurityProfile
		want bool
	}{
		{"both nil", nil, nil, true},
		{"nil vs empty type (both Intermediate)", nil, &configv1.TLSSecurityProfile{}, true},
		{"nil vs explicit Intermediate", nil, &configv1.TLSSecurityProfile{Type: configv1.TLSProfileIntermediateType}, true},
		{"Intermediate vs Modern", &configv1.TLSSecurityProfile{Type: configv1.TLSProfileIntermediateType}, &configv1.TLSSecurityProfile{Type: configv1.TLSProfileModernType}, false},
		{"nil vs Modern", nil, &configv1.TLSSecurityProfile{Type: configv1.TLSProfileModernType}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := profileEqual(tt.a, tt.b); got != tt.want {
				t.Errorf("profileEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}
