{{- /*
Internal mTLS (global.internalTLS): the cert-manager issuer the service certificates come from, and one
Certificate per service. templates/mtls.yaml renders them in the release namespace; each Certificate writes the
Secret sneakers-<service>-tls with tls.crt, tls.key and ca.crt. Defined here, not in sneakers-lib, because the
umbrella renders them with every service subchart off, when the library is not loaded.
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

