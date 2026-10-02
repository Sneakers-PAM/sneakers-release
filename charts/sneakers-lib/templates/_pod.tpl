{{- define "sneakers.volumeMounts" -}}
{{- $mounts := list (dict "name" "tmp" "mountPath" "/tmp") }}
{{- if .Values.projectedToken.enabled }}
{{- $mounts = append $mounts (dict "name" "workload-token" "mountPath" .Values.projectedToken.mountPath "readOnly" true) }}
{{- end }}
{{- if .Values.caBundle.configMap }}
{{- $mounts = append $mounts (dict "name" "ca-bundle" "mountPath" .Values.caBundle.mountPath "readOnly" true) }}
{{- end }}
{{- toYaml (concat $mounts .Values.extraVolumeMounts) }}
{{- end -}}

{{- define "sneakers.volumes" -}}
{{- $volumes := list (dict "name" "tmp" "emptyDir" (dict "sizeLimit" "64Mi")) }}
{{- with .Values.projectedToken }}
{{- if .enabled }}
{{- $token := dict "expirationSeconds" (int .expirationSeconds) "path" .path }}
{{- if .audience }}{{ $_ := set $token "audience" .audience }}{{ end }}
{{- $sources := list (dict "serviceAccountToken" $token) }}
{{- if .clusterCA }}
{{- $sources = append $sources (dict "configMap" (dict "name" "kube-root-ca.crt" "items" (list (dict "key" "ca.crt" "path" "ca.crt")))) }}
{{- end }}
{{- $volumes = append $volumes (dict "name" "workload-token" "projected" (dict "sources" $sources)) }}
{{- end }}
{{- end }}
{{- with .Values.caBundle }}
{{- if .configMap }}
{{- $volumes = append $volumes (dict "name" "ca-bundle" "configMap" (dict "name" .configMap "items" (list (dict "key" .key "path" .key)))) }}
{{- end }}
{{- end }}
{{- toYaml (concat $volumes .Values.extraVolumes) }}
{{- end -}}

{{- define "sneakers.probes" -}}
{{- with .Values.probes }}
{{- $check := dict }}
{{- if eq .type "grpc" }}
{{- $check = dict "grpc" (dict "port" (int .port)) }}
{{- else }}
{{- $check = dict "httpGet" (dict "path" .path "port" (int .port)) }}
{{- end }}
startupProbe:
  {{- toYaml $check | nindent 2 }}
  periodSeconds: 5
  failureThreshold: {{ .startupFailureThreshold }}
livenessProbe:
  {{- toYaml $check | nindent 2 }}
  periodSeconds: 10
  failureThreshold: 3
readinessProbe:
  {{- toYaml $check | nindent 2 }}
  periodSeconds: 5
  failureThreshold: 3
{{- end }}
{{- end -}}

{{- define "sneakers.ports" -}}
- name: {{ .Values.service.portName }}
  containerPort: {{ .Values.service.port }}
{{- range .Values.service.extraPorts }}
- name: {{ .name }}
  containerPort: {{ .targetPort | default .port }}
{{- end }}
{{- end -}}

{{/* The pod template shared by the Deployment. */}}
{{- define "sneakers.podTemplate" -}}
metadata:
  labels:
    {{- include "sneakers.labels" . | nindent 4 }}
    {{- with .Values.podLabels }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
  annotations:
    checksum/config: {{ include "sneakers.configData" . | sha256sum }}
    {{- with .Values.podAnnotations }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
spec:
  serviceAccountName: {{ include "sneakers.serviceAccountName" . }}
  automountServiceAccountToken: {{ .Values.serviceAccount.automountToken }}
  enableServiceLinks: false
  securityContext:
    {{- toYaml .Values.podSecurityContext | nindent 4 }}
  {{- with .Values.imagePullSecrets }}
  imagePullSecrets:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with .Values.priorityClassName }}
  priorityClassName: {{ . }}
  {{- end }}
  terminationGracePeriodSeconds: {{ .Values.terminationGracePeriodSeconds }}
  containers:
    - name: {{ .Chart.Name }}
      image: {{ include "sneakers.image" . | quote }}
      imagePullPolicy: {{ .Values.image.pullPolicy }}
      {{- with .Values.args }}
      args:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      ports:
        {{- include "sneakers.ports" . | nindent 8 }}
      envFrom:
        - configMapRef:
            name: {{ include "sneakers.fullname" . }}
        {{- range .Values.envFromSecrets }}
        - secretRef:
            name: {{ tpl . $ }}
        {{- end }}
      {{- with include "sneakers.env" . }}
      env:
        {{- . | nindent 8 }}
      {{- end }}
      {{- include "sneakers.probes" . | trim | nindent 6 }}
      resources:
        {{- toYaml .Values.resources | nindent 8 }}
      securityContext:
        {{- toYaml .Values.securityContext | nindent 8 }}
      volumeMounts:
        {{- include "sneakers.volumeMounts" . | nindent 8 }}
  volumes:
    {{- include "sneakers.volumes" . | nindent 4 }}
  {{- with .Values.nodeSelector }}
  nodeSelector:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with .Values.tolerations }}
  tolerations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with .Values.affinity }}
  affinity:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with .Values.topologySpreadConstraints }}
  topologySpreadConstraints:
    {{- tpl (toYaml .) $ | nindent 4 }}
  {{- end }}
{{- end -}}
