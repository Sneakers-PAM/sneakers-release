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

{{/*
repository[:tag][@digest]. The tag is the service's image.tag, else
global.imageTag (one tag for every service, such as an rc's 0.1.0-rc.3),
else the chart's appVersion.
*/}}
{{- define "sneakers.image" -}}
{{- $tag := .Values.image.tag | default ((.Values.global).imageTag) | default .Chart.AppVersion -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}
{{- end -}}

{{/*
The version the chart deploys, for the product's About and diagnostics, in the
appliance's form (0.1.0-rc.3, no leading v): the service's image.tag when it's
a version, else global.imageTag, else the chart's appVersion. image.tag may be
a label such as "pinned", and may carry a digest.
*/}}
{{- define "sneakers.productVersion" -}}
{{- $tag := .Values.image.tag | default "" | splitList "@" | first -}}
{{- if not (regexMatch "^v?[0-9]+\\.[0-9]+\\.[0-9]+([-+][0-9A-Za-z.+-]+)?$" $tag) -}}
{{- $tag = ((.Values.global).imageTag) | default .Chart.AppVersion -}}
{{- end -}}
{{- regexReplaceAll "^v([0-9])" $tag "${1}" -}}
{{- end -}}

{{- define "sneakers.logLevel" -}}
{{- .Values.logLevel | default ((.Values.global).logLevel) | default "error" -}}
{{- end -}}

{{- define "sneakers.logFormat" -}}
{{- .Values.logFormat | default ((.Values.global).logFormat) | default "json" -}}
{{- end -}}

{{/*
Where the workload identity tokens are mounted. The services read these paths
from the env the chart sets: the caller token (audience workloadIdentity.audience)
that a service sends on its gRPC calls, and the API token plus the cluster CA a
callee uses to fetch the cluster's signing keys.
*/}}
{{- define "sneakers.callerTokenDir" -}}/var/run/secrets/sneakers{{- end -}}
{{- define "sneakers.verifierDir" -}}/var/run/secrets/tokens{{- end -}}
