{{- /*
Internal mTLS (global.internalTLS), the pod side every service chart shares: whether a pod runs with it, its
plain health-only port and its mTLS-only port, and the directory the certificate Secret is mounted at. The
umbrella's own templates (charts/sneakers/templates/_mtls.tpl and mtls.yaml) define the issuer reference and the
Certificates; they live there because the umbrella renders them even when no service subchart is enabled, and
only an enabled subchart brings this library in.
*/ -}}

{{- /*
"true" when this service's pod runs with mTLS: global.internalTLS.enabled and the
service's own mtls.enabled (off for a service whose image has no mTLS yet).
*/ -}}
{{- define "sneakers.mtls.pod" -}}
{{- $tls := (.Values.global).internalTLS | default dict -}}
{{- $own := .Values.mtls | default dict -}}
{{- if and $tls.enabled $own.enabled -}}true{{- end -}}
{{- end -}}

{{- /* The plain health-only port a gRPC service answers the kubelet on under mTLS, or empty. */ -}}
{{- define "sneakers.mtls.healthPort" -}}
{{- if include "sneakers.mtls.pod" . -}}
{{- with (.Values.mtls | default dict).healthPort -}}{{ int . }}{{- end -}}
{{- end -}}
{{- end -}}

{{- /* The mTLS-only port a service serves besides its main one (the gateway's 9443 for mcp), or empty. */ -}}
{{- define "sneakers.mtls.port" -}}
{{- if include "sneakers.mtls.pod" . -}}
{{- with (.Values.mtls | default dict).port -}}{{ int . }}{{- end -}}
{{- end -}}
{{- end -}}

{{- define "sneakers.mtls.dir" -}}/var/run/sneakers/tls{{- end -}}
