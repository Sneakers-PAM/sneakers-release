{{/*
Non-secret settings, rendered into the ConfigMap. Values in env go through tpl,
so they can use .Values.global (for example the public host).
*/}}
{{- define "sneakers.configData" -}}
LOG_LEVEL: {{ include "sneakers.logLevel" . | quote }}
LOG_FORMAT: {{ include "sneakers.logFormat" . | quote }}
{{- with .Values.sso }}
{{- if .enabled }}
POLIS_PUBLIC_URL: {{ tpl .publicURL $ | quote }}
{{- end }}
{{- end }}
{{- range $k, $v := .Values.env }}
{{- if not (kindIs "invalid" $v) }}
{{- $value := tpl (toString $v) $ }}
{{- if ne $value "" }}
{{ $k }}: {{ $value | quote }}
{{- end }}
{{- end }}
{{- end }}
{{- end -}}

{{- define "sneakers.validate" -}}
{{- $sso := .Values.sso | default dict }}
{{- if $sso.enabled }}
{{- if not $sso.publicURL }}
{{- fail (printf "%s: sso.publicURL must be set when sso.enabled is true" (include "sneakers.fullname" .)) }}
{{- end }}
{{- if not ($sso.clientSecret).secretName }}
{{- fail (printf "%s: sso.clientSecret.secretName must name the Secret holding POLIS_CLIENT_SECRET when sso.enabled is true" (include "sneakers.fullname" .)) }}
{{- end }}
{{- else if (index .Values.env "POLIS_PUBLIC_URL") }}
{{- fail (printf "%s: set sso.enabled and sso.publicURL instead of env.POLIS_PUBLIC_URL, so the client secret is wired too" (include "sneakers.fullname" .)) }}
{{- end }}
{{- range .Values.requiredEnv }}
{{- if not (tpl (toString (index $.Values.env . | default "")) $) }}
{{- fail (printf "%s: env.%s must be set" (include "sneakers.fullname" $) .) }}
{{- end }}
{{- end }}
{{- with .Values.workloadIdentity }}
{{- if and .verify (not .callers) }}
{{- fail (printf "%s: workloadIdentity.verify needs workloadIdentity.callers" (include "sneakers.fullname" $)) }}
{{- end }}
{{- if and $.Values.projectedToken.enabled (has (trimSuffix "/" $.Values.projectedToken.mountPath) (list (include "sneakers.callerTokenDir" $) (include "sneakers.verifierDir" $))) (or .caller .verify) }}
{{- fail (printf "%s: projectedToken.mountPath %s is taken by the workload identity tokens" (include "sneakers.fullname" $) $.Values.projectedToken.mountPath) }}
{{- end }}
{{- end }}
{{- range $name, $s := .Values.secretEnv }}
{{- if and $s $s.required (not $s.secretName) (not $s.generate) }}
{{- fail (printf "%s: secretEnv.%s needs secretName (an existing Secret) or generate: true" (include "sneakers.fullname" $) $name) }}
{{- end }}
{{- end }}
{{- with .Values.certManager }}
{{- if .enabled }}
{{- if not $.Values.ingress.enabled }}
{{- fail (printf "%s: certManager.enabled needs ingress.enabled" (include "sneakers.fullname" $)) }}
{{- end }}
{{- if not $.Values.ingress.tlsSecretName }}
{{- fail (printf "%s: certManager.enabled needs ingress.tlsSecretName, the Secret the Certificate writes to" (include "sneakers.fullname" $)) }}
{{- end }}
{{- if not .issuerRef.name }}
{{- fail (printf "%s: certManager.issuerRef.name must be set when certManager.enabled is true" (include "sneakers.fullname" $)) }}
{{- end }}
{{- end }}
{{- end }}
{{- end -}}

{{/* The Secret holding generated values, named <fullname>-generated. */}}
{{- define "sneakers.generatedSecretName" -}}
{{- printf "%s-generated" (include "sneakers.fullname" .) -}}
{{- end -}}

{{- define "sneakers.hasGenerated" -}}
{{- range $name, $s := .Values.secretEnv }}{{ if and $s $s.generate (not $s.secretName) }}true{{ end }}{{ end -}}
{{- end -}}

{{/*
Container env: secret-backed settings (secretEnv), the projected token, the
workload identity settings and the CA bundle paths, then extraEnv. Used by the Deployment and the migration Job.
*/}}
{{- define "sneakers.env" -}}
{{- $env := list }}
{{- range $name, $s := .Values.secretEnv }}
{{- if $s }}
{{- if $s.secretName }}
{{- $ref := dict "name" (tpl $s.secretName $) "key" ($s.key | default $name) }}
{{- if not $s.required }}{{ $_ := set $ref "optional" true }}{{ end }}
{{- $env = append $env (dict "name" $name "valueFrom" (dict "secretKeyRef" $ref)) }}
{{- else if $s.generate }}
{{- $env = append $env (dict "name" $name "valueFrom" (dict "secretKeyRef" (dict "name" (include "sneakers.generatedSecretName" $) "key" $name))) }}
{{- end }}
{{- end }}
{{- end }}
{{- with .Values.projectedToken }}
{{- if and .enabled .envName }}
{{- $env = append $env (dict "name" .envName "value" (printf "%s/%s" .mountPath .path)) }}
{{- end }}
{{- end }}
{{- with .Values.sso }}
{{- if .enabled }}
{{- $env = append $env (dict "name" "POLIS_CLIENT_SECRET" "valueFrom" (dict "secretKeyRef" (dict "name" (tpl .clientSecret.secretName $) "key" (.clientSecret.key | default "POLIS_CLIENT_SECRET")))) }}
{{- end }}
{{- end }}
{{- with .Values.workloadIdentity }}
{{- if .caller }}
{{- $env = append $env (dict "name" "WORKLOAD_TOKEN_FILE" "value" (printf "%s/token" (include "sneakers.callerTokenDir" $))) }}
{{- end }}
{{- if .verify }}
{{- $dir := include "sneakers.verifierDir" $ }}
{{- $allowed := list }}
{{- range .callers }}{{ $allowed = append $allowed (printf "%s/sneakers-%s" $.Release.Namespace .) }}{{ end }}
{{- $env = append $env (dict "name" "WORKLOAD_OIDC_ISSUER" "value" .issuer) }}
{{- $env = append $env (dict "name" "WORKLOAD_OIDC_JWKS_URL" "value" .jwksURL) }}
{{- $env = append $env (dict "name" "WORKLOAD_OIDC_CA_FILE" "value" (printf "%s/ca.crt" $dir)) }}
{{- $env = append $env (dict "name" "WORKLOAD_OIDC_BEARER_FILE" "value" (printf "%s/token" $dir)) }}
{{- $env = append $env (dict "name" "WORKLOAD_AUDIENCE" "value" .audience) }}
{{- $env = append $env (dict "name" "WORKLOAD_ALLOWED_SERVICEACCOUNTS" "value" (join "," $allowed)) }}
{{- end }}
{{- end }}
{{- with .Values.caBundle }}
{{- if and .configMap .envName }}
{{- $env = append $env (dict "name" .envName "value" (printf "%s/%s" .mountPath .key)) }}
{{- end }}
{{- end }}
{{- $env = concat $env .Values.extraEnv }}
{{- if $env }}{{ tpl (toYaml $env) . }}{{ end }}
{{- end -}}
