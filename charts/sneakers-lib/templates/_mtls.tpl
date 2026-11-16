{{- /*
Internal mTLS (global.internalTLS): the cert-manager issuer the service
certificates come from, and one Certificate per service. The umbrella renders
them (charts/sneakers/templates/mtls.yaml) in the release namespace; each
Certificate writes the Secret sneakers-<service>-tls with tls.crt, tls.key and
ca.crt.
*/ -}}

{{- /* The issuer reference for every service Certificate: the chart's own CA Issuer, or the cluster's. */ -}}
{{- define "sneakers.mtls.issuerRef" -}}
{{- $tls := (.Values.global).internalTLS | default dict -}}
{{- $ref := $tls.issuerRef | default dict -}}
name: {{ $ref.name | default "sneakers-mtls" }}
kind: {{ $ref.kind | default "Issuer" }}
group: {{ $ref.group | default "cert-manager.io" }}
{{- end -}}

{{- /* True (as "true") when the chart creates the bootstrap Issuer, the root CA and the CA Issuer. */ -}}
{{- define "sneakers.mtls.createsCA" -}}
{{- $tls := (.Values.global).internalTLS | default dict -}}
{{- if not (($tls.issuerRef | default dict).name) -}}true{{- end -}}
{{- end -}}

{{- /*
One service Certificate. Call with (dict "root" $ "service" "vault"). The short
Service name is a SAN, because the services dial short names such as
sneakers-vault:9091; the URI SAN carries the service account the workload token
names. ECDSA P-256, 30 days, renewed at two thirds.
*/ -}}
{{- define "sneakers.mtls.certificate" -}}
{{- $root := .root -}}
{{- $name := printf "sneakers-%s" .service -}}
{{- $ns := $root.Release.Namespace -}}
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: {{ $name }}
  namespace: {{ $ns }}
  labels:
    app.kubernetes.io/name: {{ $name }}
    app.kubernetes.io/instance: {{ $root.Release.Name }}
    app.kubernetes.io/part-of: sneakers
    app.kubernetes.io/component: {{ .service }}
    app.kubernetes.io/managed-by: {{ $root.Release.Service }}
spec:
  secretName: {{ $name }}-tls
  duration: 720h
  renewBefore: 240h
  usages:
    - server auth
    - client auth
  privateKey:
    algorithm: ECDSA
    size: 256
    rotationPolicy: Always
  dnsNames:
    - {{ $name }}
    - {{ $name }}.{{ $ns }}
    - {{ $name }}.{{ $ns }}.svc
    - {{ $name }}.{{ $ns }}.svc.cluster.local
  uris:
    - spiffe://sneakers/ns/{{ $ns }}/sa/{{ $name }}
  issuerRef:
    {{- include "sneakers.mtls.issuerRef" $root | nindent 4 }}
{{- end -}}

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
