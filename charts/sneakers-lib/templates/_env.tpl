{{/*
Non-secret settings, rendered into the ConfigMap. Values in env go through tpl,
so they can use .Values.global (for example the public host).
*/}}
{{- define "sneakers.configData" -}}
LOG_LEVEL: {{ include "sneakers.logLevel" . | quote }}
LOG_FORMAT: {{ include "sneakers.logFormat" . | quote }}
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
{{- range .Values.requiredEnv }}
{{- if not (tpl (toString (index $.Values.env . | default "")) $) }}
{{- fail (printf "%s: env.%s must be set" (include "sneakers.fullname" $) .) }}
{{- end }}
{{- end }}
{{- range $name, $s := .Values.secretEnv }}
{{- if and $s $s.required (not $s.secretName) (not $s.generate) }}
{{- fail (printf "%s: secretEnv.%s needs secretName (an existing Secret) or generate: true" (include "sneakers.fullname" $) $name) }}
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
Container env: secret-backed settings (secretEnv), the projected token and CA
bundle paths, then extraEnv. Used by the Deployment and the migration Job.
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
{{- with .Values.caBundle }}
{{- if and .configMap .envName }}
{{- $env = append $env (dict "name" .envName "value" (printf "%s/%s" .mountPath .key)) }}
{{- end }}
{{- end }}
{{- $env = concat $env .Values.extraEnv }}
{{- if $env }}{{ tpl (toYaml $env) . }}{{ end }}
{{- end -}}
