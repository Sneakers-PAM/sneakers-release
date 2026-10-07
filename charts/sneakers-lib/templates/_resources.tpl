{{- define "sneakers.configmap" -}}
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ include "sneakers.fullname" . }}
  labels:
    {{- include "sneakers.labels" . | nindent 4 }}
data:
  {{- include "sneakers.configData" . | nindent 2 }}
{{- end -}}

{{- define "sneakers.deployment" -}}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "sneakers.fullname" . }}
  labels:
    {{- include "sneakers.labels" . | nindent 4 }}
spec:
  {{- if not .Values.autoscaling.enabled }}
  replicas: {{ .Values.replicas }}
  {{- end }}
  revisionHistoryLimit: 5
  strategy:
    type: {{ .Values.strategy }}
  selector:
    matchLabels:
      {{- include "sneakers.selectorLabels" . | nindent 6 }}
  template:
    {{- include "sneakers.podTemplate" . | nindent 4 }}
{{- end -}}

{{- define "sneakers.service" -}}
apiVersion: v1
kind: Service
metadata:
  name: {{ include "sneakers.fullname" . }}
  labels:
    {{- include "sneakers.labels" . | nindent 4 }}
spec:
  type: ClusterIP
  selector:
    {{- include "sneakers.selectorLabels" . | nindent 4 }}
  ports:
    - name: {{ .Values.service.portName }}
      port: {{ .Values.service.port }}
      targetPort: {{ .Values.service.portName }}
      {{- if eq .Values.service.portName "grpc" }}
      appProtocol: grpc
      {{- end }}
    {{- range .Values.service.extraPorts }}
    - name: {{ .name }}
      port: {{ .port }}
      targetPort: {{ .name }}
    {{- end }}
{{- end -}}

{{- define "sneakers.serviceAccount" -}}
{{- if .Values.serviceAccount.create }}
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{ include "sneakers.serviceAccountName" . }}
  labels:
    {{- include "sneakers.labels" . | nindent 4 }}
automountServiceAccountToken: false
{{- end }}
{{- end -}}

{{/*
Ingress on the main port is allowed only from the services named in
workloadIdentity.callers (matched by their component label in this release),
and from the peers in networkPolicy.ingressFrom on networkPolicy.ingressPorts,
which an edge service uses for its ingress controller. Everything else is
refused, including other pods of the release.
*/}}
{{- define "sneakers.networkPolicy" -}}
{{- if .Values.networkPolicy.enabled }}
{{- $callers := .Values.workloadIdentity.callers }}
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {{ include "sneakers.fullname" . }}
  labels:
    {{- include "sneakers.labels" . | nindent 4 }}
spec:
  podSelector:
    matchLabels:
      {{- include "sneakers.selectorLabels" . | nindent 6 }}
  policyTypes:
    - Ingress
    {{- if .Values.networkPolicy.egress }}
    - Egress
    {{- end }}
  {{- if or $callers .Values.networkPolicy.ingressFrom }}
  ingress:
    {{- range $callers }}
    - from:
        - podSelector:
            matchLabels:
              app.kubernetes.io/part-of: sneakers
              app.kubernetes.io/component: {{ . }}
              app.kubernetes.io/instance: {{ $.Release.Name }}
      ports:
        - port: {{ $.Values.service.portName }}
    {{- end }}
    {{- with .Values.networkPolicy.ingressFrom }}
    - from:
        {{- toYaml . | nindent 8 }}
      ports:
        {{- range $.Values.networkPolicy.ingressPorts }}
        - port: {{ . }}
        {{- end }}
    {{- end }}
  {{- else }}
  ingress: []
  {{- end }}
  {{- with .Values.networkPolicy.egress }}
  egress:
    {{- toYaml . | nindent 4 }}
  {{- end }}
{{- end }}
{{- end -}}

{{/* A budget only makes sense with more than one pod. */}}
{{- define "sneakers.pdb" -}}
{{- if and .Values.podDisruptionBudget.enabled (or .Values.autoscaling.enabled (gt (int .Values.replicas) 1)) }}
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: {{ include "sneakers.fullname" . }}
  labels:
    {{- include "sneakers.labels" . | nindent 4 }}
spec:
  {{- if .Values.podDisruptionBudget.maxUnavailable }}
  maxUnavailable: {{ .Values.podDisruptionBudget.maxUnavailable }}
  {{- else }}
  minAvailable: {{ .Values.podDisruptionBudget.minAvailable }}
  {{- end }}
  selector:
    matchLabels:
      {{- include "sneakers.selectorLabels" . | nindent 6 }}
{{- end }}
{{- end -}}

{{- define "sneakers.hpa" -}}
{{- if .Values.autoscaling.enabled }}
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: {{ include "sneakers.fullname" . }}
  labels:
    {{- include "sneakers.labels" . | nindent 4 }}
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: {{ include "sneakers.fullname" . }}
  minReplicas: {{ .Values.autoscaling.minReplicas }}
  maxReplicas: {{ .Values.autoscaling.maxReplicas }}
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: {{ .Values.autoscaling.targetCPUUtilizationPercentage }}
{{- end }}
{{- end -}}

{{- define "sneakers.ingress" -}}
{{- if .Values.ingress.enabled }}
{{- if not .Values.ingress.host }}
{{- fail (printf "%s: ingress.host must be set when ingress.enabled is true" (include "sneakers.fullname" .)) }}
{{- end }}
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: {{ include "sneakers.fullname" . }}
  labels:
    {{- include "sneakers.labels" . | nindent 4 }}
  {{- with .Values.ingress.annotations }}
  annotations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
spec:
  {{- with .Values.ingress.className }}
  ingressClassName: {{ . }}
  {{- end }}
  {{- with .Values.ingress.tlsSecretName }}
  tls:
    - hosts: [{{ tpl $.Values.ingress.host $ | quote }}]
      secretName: {{ . }}
  {{- end }}
  rules:
    - host: {{ tpl .Values.ingress.host . | quote }}
      http:
        paths:
          {{- range .Values.ingress.paths }}
          - path: {{ .path }}
            pathType: {{ .pathType | default "Prefix" }}
            backend:
              service:
                name: {{ include "sneakers.fullname" $ }}
                port:
                  name: {{ .portName | default $.Values.service.portName }}
          {{- end }}
{{- end }}
{{- end -}}

{{/*
The chart never creates an Issuer, a ClusterIssuer or any cert-manager CRD or
webhook: certManager.enabled only asks the cluster's existing cert-manager for
one Certificate, pointed at issuerRef, writing the Secret ingress.tlsSecretName
already names.
*/}}
{{- define "sneakers.certificate" -}}
{{- if (.Values.certManager).enabled }}
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: {{ include "sneakers.fullname" . }}
  labels:
    {{- include "sneakers.labels" . | nindent 4 }}
spec:
  secretName: {{ .Values.ingress.tlsSecretName }}
  dnsNames: [{{ tpl .Values.ingress.host . | quote }}]
  issuerRef:
    name: {{ .Values.certManager.issuerRef.name }}
    kind: {{ .Values.certManager.issuerRef.kind | default "ClusterIssuer" }}
    group: {{ .Values.certManager.issuerRef.group | default "cert-manager.io" }}
{{- end }}
{{- end -}}

{{/*
Values the chart generates once (secretEnv entries with generate: true and no
secretName). They are kept on upgrade and on uninstall: a lost root key makes
every stored secret unreadable, so back this Secret up with the database.
*/}}
{{- define "sneakers.generatedSecret" -}}
{{- if include "sneakers.hasGenerated" . }}
{{- $name := include "sneakers.generatedSecretName" . }}
{{- $existing := (lookup "v1" "Secret" .Release.Namespace $name).data | default dict }}
apiVersion: v1
kind: Secret
metadata:
  name: {{ $name }}
  labels:
    {{- include "sneakers.labels" . | nindent 4 }}
  annotations:
    helm.sh/resource-policy: keep
type: Opaque
data:
  {{- range $key, $s := .Values.secretEnv }}
  {{- if and $s $s.generate (not $s.secretName) }}
  {{ $key }}: {{ index $existing $key | default (randBytes (int ($s.bytes | default 32)) | b64enc) }}
  {{- end }}
  {{- end }}
{{- end }}
{{- end -}}

{{/*
A pre-upgrade Job that runs the service image with migrations.job.args, so the
schema moves before any new pod starts. Off by default: the service binaries
apply their migrations at start (under an advisory lock) and have no
migrate-only command yet.
*/}}
{{- define "sneakers.migrationJob" -}}
{{- if .Values.migrations.job.enabled }}
apiVersion: batch/v1
kind: Job
metadata:
  name: {{ printf "%s-migrate" (include "sneakers.fullname" .) | trunc 63 | trimSuffix "-" }}
  labels:
    {{- include "sneakers.labels" . | nindent 4 }}
  annotations:
    helm.sh/hook: pre-upgrade
    helm.sh/hook-weight: "0"
    helm.sh/hook-delete-policy: before-hook-creation,hook-succeeded
spec:
  backoffLimit: 3
  activeDeadlineSeconds: {{ .Values.migrations.job.activeDeadlineSeconds }}
  template:
    metadata:
      labels:
        {{- include "sneakers.labels" . | nindent 8 }}
    spec:
      restartPolicy: Never
      serviceAccountName: {{ include "sneakers.serviceAccountName" . }}
      automountServiceAccountToken: false
      enableServiceLinks: false
      securityContext:
        {{- toYaml .Values.podSecurityContext | nindent 8 }}
      {{- with .Values.imagePullSecrets }}
      imagePullSecrets:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      containers:
        - name: migrate
          image: {{ include "sneakers.image" . | quote }}
          imagePullPolicy: {{ .Values.image.pullPolicy }}
          args:
            {{- toYaml .Values.migrations.job.args | nindent 12 }}
          env:
            {{- range $k, $v := fromYaml (include "sneakers.configData" .) }}
            - name: {{ $k }}
              value: {{ $v | quote }}
            {{- end }}
            {{- with include "sneakers.env" . }}
            {{- . | nindent 12 }}
            {{- end }}
          resources:
            {{- toYaml .Values.resources | nindent 12 }}
          securityContext:
            {{- toYaml .Values.securityContext | nindent 12 }}
          volumeMounts:
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: tmp
          emptyDir:
            sizeLimit: 64Mi
{{- end }}
{{- end -}}

{{/* Everything a service chart renders. */}}
{{- define "sneakers.all" -}}
{{- include "sneakers.validate" . }}
{{- $docs := list
  (include "sneakers.serviceAccount" .)
  (include "sneakers.generatedSecret" .)
  (include "sneakers.configmap" .)
  (include "sneakers.deployment" .)
  (include "sneakers.service" .)
  (include "sneakers.networkPolicy" .)
  (include "sneakers.pdb" .)
  (include "sneakers.hpa" .)
  (include "sneakers.ingress" .)
  (include "sneakers.certificate" .)
  (include "sneakers.migrationJob" .) }}
{{- range $docs }}
{{- if trim . }}
---
{{ trim . }}
{{- end }}
{{- end }}
{{- end -}}
