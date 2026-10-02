{{/*
Names and labels. Every service keeps a fixed name, sneakers-<chart>, so the
services find each other by the addresses in their defaults. One release per
namespace.
*/}}
{{- define "sneakers.fullname" -}}
{{- .Values.fullnameOverride | default (printf "sneakers-%s" .Chart.Name) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "sneakers.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sneakers.fullname" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "sneakers.labels" -}}
{{ include "sneakers.selectorLabels" . }}
app.kubernetes.io/part-of: sneakers
app.kubernetes.io/component: {{ .Chart.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end -}}

{{- define "sneakers.serviceAccountName" -}}
{{- .Values.serviceAccount.name | default (include "sneakers.fullname" .) -}}
{{- end -}}

{{/* repository[:tag][@digest]; the tag defaults to the chart's appVersion. */}}
{{- define "sneakers.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}
{{- end -}}

{{- define "sneakers.logLevel" -}}
{{- .Values.logLevel | default ((.Values.global).logLevel) | default "error" -}}
{{- end -}}

{{- define "sneakers.logFormat" -}}
{{- .Values.logFormat | default ((.Values.global).logFormat) | default "json" -}}
{{- end -}}
