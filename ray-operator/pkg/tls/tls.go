package tls

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

var log = ctrl.Log.WithName("tls")

// openSSLToIANA converts the OpenSSL cipher names used by OpenShift TLS
// profiles (configv1.TLSProfiles and Custom profiles) to the IANA names
// reported by crypto/tls. IANA names, including the TLS 1.3 suite names,
// pass through unchanged and are not listed here.
var openSSLToIANA = map[string]string{
	"ECDHE-ECDSA-AES128-GCM-SHA256": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	"ECDHE-RSA-AES128-GCM-SHA256":   "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	"ECDHE-ECDSA-AES256-GCM-SHA384": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	"ECDHE-RSA-AES256-GCM-SHA384":   "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	"ECDHE-ECDSA-CHACHA20-POLY1305": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
	"ECDHE-RSA-CHACHA20-POLY1305":   "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	"ECDHE-ECDSA-AES128-SHA256":     "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
	"ECDHE-RSA-AES128-SHA256":       "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	"ECDHE-ECDSA-AES256-SHA384":     "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
	"ECDHE-RSA-AES256-SHA384":       "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
	"ECDHE-ECDSA-AES128-SHA":        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	"ECDHE-RSA-AES128-SHA":          "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	"ECDHE-ECDSA-AES256-SHA":        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	"ECDHE-RSA-AES256-SHA":          "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	"AES128-GCM-SHA256":             "TLS_RSA_WITH_AES_128_GCM_SHA256",
	"AES256-GCM-SHA384":             "TLS_RSA_WITH_AES_256_GCM_SHA384",
	"AES128-SHA256":                 "TLS_RSA_WITH_AES_128_CBC_SHA256",
	"AES256-SHA256":                 "TLS_RSA_WITH_AES_256_CBC_SHA256",
	"AES128-SHA":                    "TLS_RSA_WITH_AES_128_CBC_SHA",
	"AES256-SHA":                    "TLS_RSA_WITH_AES_256_CBC_SHA",
	"DES-CBC3-SHA":                  "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
}

// ianaCipherSuites maps IANA cipher suite names to Go IDs, built from the
// crypto/tls runtime tables so that suites this Go build cannot negotiate
// are never offered. InsecureCipherSuites is included on purpose: the Old
// profile contains suites (e.g. 3DES) that only appear there.
var ianaCipherSuites = func() map[string]uint16 {
	m := make(map[string]uint16)
	for _, cs := range tls.CipherSuites() {
		m[cs.Name] = cs.ID
	}
	for _, cs := range tls.InsecureCipherSuites() {
		m[cs.Name] = cs.ID
	}
	return m
}()

// isTLS13CipherID reports whether id is a TLS 1.3-only cipher suite
// (0x1300-0x13ff), which cannot be used for TLS 1.2 and below.
func isTLS13CipherID(id uint16) bool {
	return id >= 0x1300 && id <= 0x13ff
}

var intermediateCiphers = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
}

var tlsVersionMap = map[configv1.TLSProtocolVersion]uint16{
	"VersionTLS10": tls.VersionTLS10,
	"VersionTLS11": tls.VersionTLS11,
	"VersionTLS12": tls.VersionTLS12,
	"VersionTLS13": tls.VersionTLS13,
}

// Result holds the resolved TLS configuration.
type Result struct {
	TLSOpts        []func(*tls.Config)
	Profile        *configv1.TLSSecurityProfile
	Adherence      configv1.TLSAdherencePolicy
	ProfileFetched bool
}

// Resolve reads the cluster TLS profile from apiservers.config.openshift.io/cluster
// and returns TLS option functions for controller-runtime servers.
// On non-OpenShift clusters or when the API is temporarily unavailable,
// it returns hardened Intermediate defaults.
// Returns an error only on unexpected failures that should prevent startup.
func Resolve(ctx context.Context, cfg *rest.Config) (Result, error) {
	scheme := runtime.NewScheme()
	if err := configv1.Install(scheme); err != nil {
		return Result{}, fmt.Errorf("installing OpenShift config scheme: %w", err)
	}

	// Bound the bootstrap client's requests, including REST mapper discovery,
	// which the caller's context does not cover.
	bootstrapCfg := rest.CopyConfig(cfg)
	bootstrapCfg.Timeout = 10 * time.Second
	k8sClient, err := client.New(bootstrapCfg, client.Options{Scheme: scheme})
	if err != nil {
		return Result{}, fmt.Errorf("creating bootstrap client for TLS profile: %w", err)
	}

	return resolveWithClient(ctx, k8sClient)
}

func resolveWithClient(ctx context.Context, k8sClient client.Client) (Result, error) {
	var result Result

	resolveCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	apiServer := &configv1.APIServer{}
	if err := k8sClient.Get(resolveCtx, client.ObjectKey{Name: "cluster"}, apiServer); err != nil {
		switch {
		case meta.IsNoMatchError(err):
			log.Info("TLS profile not available, using hardened defaults (non-OpenShift cluster)")
		case apierrors.IsNotFound(err):
			log.Info("APIServer resource not found, using hardened defaults")
		case apierrors.IsServiceUnavailable(err),
			apierrors.IsTimeout(err),
			apierrors.IsServerTimeout(err),
			apierrors.IsTooManyRequests(err),
			errors.Is(err, context.DeadlineExceeded):
			log.Info("Transient API error reading TLS profile, using hardened defaults", "error", err)
			result.ProfileFetched = true
			result.Profile = &configv1.TLSSecurityProfile{Type: configv1.TLSProfileIntermediateType}
		default:
			// Fail closed: anything but a missing API/resource or a transient
			// error (e.g. Forbidden, Unauthorized) must stop startup.
			return result, fmt.Errorf("reading APIServer TLS profile: %w "+
				"(hint: verify the operator service account has RBAC to get apiservers.config.openshift.io/cluster)", err)
		}
		result.TLSOpts = append(result.TLSOpts, intermediateWithALPN)
		return result, nil
	}

	result.ProfileFetched = true
	result.Profile = apiServer.Spec.TLSSecurityProfile
	result.Adherence = apiServer.Spec.TLSAdherence
	minVersion, ciphers, err := parseProfile(apiServer.Spec.TLSSecurityProfile, apiServer.Spec.TLSAdherence)
	if err != nil {
		return result, fmt.Errorf("parsing cluster TLS profile: %w", err)
	}

	result.TLSOpts = append(result.TLSOpts, func(c *tls.Config) {
		c.MinVersion = minVersion
		// Go ignores CipherSuites for TLS 1.3+; never set them there.
		if len(ciphers) > 0 && minVersion < tls.VersionTLS13 {
			c.CipherSuites = ciphers
		}
		c.NextProtos = []string{"h2", "http/1.1"}
	})
	return result, nil
}

func intermediateWithALPN(c *tls.Config) {
	c.MinVersion = tls.VersionTLS12
	c.CipherSuites = intermediateCiphers
	c.NextProtos = []string{"h2", "http/1.1"}
}

// shouldHonorClusterTLSProfile reports whether the operator must follow the
// cluster TLS profile instead of its own hardened Intermediate defaults.
// Local copy of the openshift/library-go semantics: false for NoOpinion("")
// and LegacyAdheringComponentsOnly; true for StrictAllComponents and any
// unknown value (fail secure, forward compatible).
func shouldHonorClusterTLSProfile(adherence configv1.TLSAdherencePolicy) bool {
	switch adherence {
	case configv1.TLSAdherencePolicyNoOpinion, configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly:
		return false
	default:
		return true
	}
}

// parseProfile maps a cluster TLSSecurityProfile to a Go minimum TLS version
// and cipher suite list. An error means the profile is unusable and the
// operator must fail closed at startup.
func parseProfile(profile *configv1.TLSSecurityProfile, adherence configv1.TLSAdherencePolicy) (uint16, []uint16, error) {
	if profile == nil {
		return parseNamedProfile(configv1.TLSProfileIntermediateType)
	}

	if !shouldHonorClusterTLSProfile(adherence) {
		log.Info("TLS adherence policy does not require honoring the cluster profile, using Intermediate", "adherence", adherence)
		return parseNamedProfile(configv1.TLSProfileIntermediateType)
	}

	switch profile.Type {
	case "":
		return parseNamedProfile(configv1.TLSProfileIntermediateType)
	case configv1.TLSProfileCustomType:
		if profile.Custom == nil {
			return 0, nil, fmt.Errorf("custom TLS profile type specified but custom block is nil")
		}
		return parseCustomProfile(profile.Custom)
	default:
		return parseNamedProfile(profile.Type)
	}
}

// parseSpec maps a profile spec's minimum version and cipher names to Go
// values, pruning cipher names this Go build cannot negotiate at that version.
// Go 1.22+ defaults the server minimum to TLS 1.2 only when
// tls.Config.MinVersion is unset; the explicit minimum set here needs no GODEBUG.
func parseSpec(spec *configv1.TLSProfileSpec, label string) (uint16, []uint16, error) {
	minVersion, err := minTLSVersion(spec.MinTLSVersion)
	if err != nil {
		return 0, nil, err
	}
	if len(spec.Ciphers) == 0 {
		return minVersion, nil, nil
	}

	ciphers := usableCipherSuites(spec.Ciphers, minVersion)
	if len(ciphers) == 0 {
		return 0, nil, fmt.Errorf("%s contains no usable cipher suites for minimum TLS version %s", label, spec.MinTLSVersion)
	}
	return minVersion, ciphers, nil
}

// parseNamedProfile resolves a built-in profile from the configv1.TLSProfiles
// table.
func parseNamedProfile(profileType configv1.TLSProfileType) (uint16, []uint16, error) {
	spec, ok := configv1.TLSProfiles[profileType]
	if !ok || spec == nil {
		return 0, nil, fmt.Errorf("unknown TLS profile type %q", profileType)
	}

	return parseSpec(spec, fmt.Sprintf("TLS profile %q", profileType))
}

func parseCustomProfile(custom *configv1.CustomTLSProfile) (uint16, []uint16, error) {
	return parseSpec(&custom.TLSProfileSpec, fmt.Sprintf("custom TLS profile ciphers %v", custom.Ciphers))
}

func minTLSVersion(v configv1.TLSProtocolVersion) (uint16, error) {
	if minVersion, ok := tlsVersionMap[v]; ok {
		return minVersion, nil
	}
	return 0, fmt.Errorf("unknown minTLSVersion %q", v)
}

// usableCipherSuites maps profile cipher names (IANA or OpenSSL) to Go IDs,
// keeping only suites this Go build can negotiate at or above minVersion.
// Unknown names are logged and dropped. TLS 1.3-only suites are expected in
// profile lists alongside <=1.2 suites and are silently excluded below TLS 1.3.
func usableCipherSuites(names []string, minVersion uint16) []uint16 {
	var ciphers []uint16
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		iana := name
		if _, ok := ianaCipherSuites[iana]; !ok {
			if alias, ok := openSSLToIANA[name]; ok {
				iana = alias
			}
		}
		id, ok := ianaCipherSuites[iana]
		if !ok {
			log.Info("Dropping unsupported cipher from TLS profile", "cipher", name)
			continue
		}
		if minVersion < tls.VersionTLS13 && isTLS13CipherID(id) {
			continue
		}
		ciphers = append(ciphers, id)
	}
	return ciphers
}

// SetupWatcher registers a controller that watches the APIServer resource
// and triggers a graceful restart when the TLS profile changes.
// On non-OpenShift clusters (ProfileFetched == false), this is a no-op.
func SetupWatcher(mgr manager.Manager, result Result, cancel context.CancelFunc) error {
	if !result.ProfileFetched {
		return nil
	}

	c, err := controller.New("tls-profile-watcher", mgr, controller.Options{
		NeedLeaderElection: boolPtr(false),
		Reconciler: &profileWatcher{
			client:           mgr.GetClient(),
			cancel:           cancel,
			initialProfile:   result.Profile,
			initialAdherence: result.Adherence,
		},
	})
	if err != nil {
		return fmt.Errorf("creating TLS profile watcher controller: %w", err)
	}

	if err := c.Watch(source.Kind(
		mgr.GetCache(),
		&configv1.APIServer{},
		handler.TypedEnqueueRequestsFromMapFunc(
			func(_ context.Context, obj *configv1.APIServer) []reconcile.Request {
				if obj.Name == "cluster" {
					return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: "cluster"}}}
				}
				return nil
			},
		),
	)); err != nil {
		return fmt.Errorf("watching APIServer resource: %w", err)
	}

	log.Info("TLS profile watcher registered")
	return nil
}

type profileWatcher struct {
	client           client.Client
	cancel           context.CancelFunc
	initialProfile   *configv1.TLSSecurityProfile
	initialAdherence configv1.TLSAdherencePolicy
}

func (w *profileWatcher) Reconcile(ctx context.Context, _ reconcile.Request) (reconcile.Result, error) {
	apiServer := &configv1.APIServer{}
	if err := w.client.Get(ctx, client.ObjectKey{Name: "cluster"}, apiServer); err != nil {
		log.Info("TLS profile watcher: unable to read APIServer, will retry", "error", err)
		return reconcile.Result{}, err
	}

	current := apiServer.Spec.TLSSecurityProfile
	// A change in the adherence gate (e.g. NoOpinion -> StrictAllComponents)
	// changes the effective profile even when the profile itself is unchanged.
	if shouldHonorClusterTLSProfile(w.initialAdherence) != shouldHonorClusterTLSProfile(apiServer.Spec.TLSAdherence) ||
		!profileEqual(w.initialProfile, current) {
		log.Info("TLS profile or adherence policy changed, initiating shutdown to reload")
		w.cancel()
	}
	return reconcile.Result{}, nil
}

func normalizeProfileType(t configv1.TLSProfileType) configv1.TLSProfileType {
	if t == "" {
		return configv1.TLSProfileIntermediateType
	}
	return t
}

func normalizeProfile(p *configv1.TLSSecurityProfile) *configv1.TLSSecurityProfile {
	if p == nil {
		return &configv1.TLSSecurityProfile{Type: configv1.TLSProfileIntermediateType}
	}
	return p
}

func profileEqual(a, b *configv1.TLSSecurityProfile) bool {
	a = normalizeProfile(a)
	b = normalizeProfile(b)
	if normalizeProfileType(a.Type) != normalizeProfileType(b.Type) {
		return false
	}
	if normalizeProfileType(a.Type) == configv1.TLSProfileCustomType {
		if a.Custom == nil && b.Custom == nil {
			return true
		}
		if a.Custom == nil || b.Custom == nil {
			return false
		}
		if a.Custom.MinTLSVersion != b.Custom.MinTLSVersion {
			return false
		}
		if len(a.Custom.Ciphers) != len(b.Custom.Ciphers) {
			return false
		}
		for i := range a.Custom.Ciphers {
			if a.Custom.Ciphers[i] != b.Custom.Ciphers[i] {
				return false
			}
		}
	}
	return true
}

func boolPtr(b bool) *bool { return &b }
