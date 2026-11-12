{{- define "helpers.pod.containerImage" -}}

{{- if .Values.image.tag }}
{{- printf "%s/%s/%s:%s" .Values.image.registry .Values.image.repository .Values.image.name .Values.image.tag }}
{{- else }}
{{- printf "%s/%s/%s:%s" .Values.image.registry .Values.image.repository .Values.image.name .Chart.AppVersion }}
{{- end }}

{{- end -}}

{{- define "helpers.pod.uiImage" -}}

{{- if .Values.ui.image.tag }}
{{- printf "%s/%s/%s:%s" .Values.ui.image.registry .Values.ui.image.repository .Values.ui.image.name .Values.ui.image.tag }}
{{- else }}
{{- printf "%s/%s/%s:%s" .Values.ui.image.registry .Values.ui.image.repository .Values.ui.image.name "main" }}
{{- end }}

{{- end -}}

{{- define "helpers.pod.initContainers" -}}

{{- $all := . -}}
{{- range $k, $v := .Values.initContainers }}
- name: {{ $v.name }}
  {{- if $v.image }}
  image: {{ $v.image }}
  {{- else }}
  image: {{ include "helpers.pod.containerImage" $all | quote }}
  {{- end }}
  {{- if $v.imagePullPolicy }}
  imagePullPolicy: {{ $v.imagePullPolicy }}
  {{- else }}
  imagePullPolicy: {{ $all.Values.global.imagePullPolicy }}
  {{- end }}
  {{- if $all.Values.env }}
  env:
    {{- include "helpers.pod.envs" $all | nindent 4 }}
  {{- end }}
  command: {{- include "helpers.common.tplvalues.render" (dict "value" $v.command "context" $) | nindent 4 }}

{{- end }}

{{- end -}}

{{- define "helpers.pod.envs" -}}

{{- $env := deepCopy (.Values.env | default dict) }}
{{- if not .Values.config.enabled }}
{{- $env = merge $env (deepCopy (.Values.defaultEnv | default dict)) }}
{{- end }}
{{- $_ := unset $env "UPF_API_TOKEN" }}
- name: UPF_API_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ include "eupf.apiSecretName" . }}
      key: api-token
{{- if .Values.api.tls.existingSecret }}
- name: UPF_API_TLS_CERT_FILE
  value: /etc/eupf/tls/tls.crt
- name: UPF_API_TLS_KEY_FILE
  value: /etc/eupf/tls/tls.key
{{- $_ := unset $env "UPF_API_TLS_CERT_FILE" }}
{{- $_ := unset $env "UPF_API_TLS_KEY_FILE" }}
{{- end }}

{{- range $name, $value := $env }}
- name: {{ $name }}
  value: {{ $value | quote }}
{{- end }}

{{- end -}}

{{/*
Container args: user-provided args, prefixed with `--config <config.path>`
when the ConfigMap-based configuration mode is enabled.
*/}}
{{- define "helpers.pod.args" -}}
{{- $args := .Values.args | default list }}
{{- if .Values.config.enabled }}
{{- $args = prepend (prepend $args .Values.config.path) "--config" }}
{{- end }}
{{- include "helpers.common.tplvalues.render" (dict "value" $args "context" $) }}
{{- end -}}

{{- define "helpers.pod.probes" -}}

{{- with .Values.livenessProbe }}
livenessProbe:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.readinessProbe }}
readinessProbe:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.startupProbe }}
startupProbe:
  {{- toYaml . | nindent 2 }}
{{- end }}

{{- end -}}

{{- define "helpers.pod.volumes" -}}

{{- $volumes := .Values.volumes | default list }}
{{- if .Values.api.tls.existingSecret }}
{{- $volumes = append $volumes (dict "name" "api-tls" "secret" (dict "secretName" .Values.api.tls.existingSecret)) }}
{{- end }}
{{- if .Values.config.enabled }}
{{- $configVolume := dict "name" "config" "configMap" (dict "name" (printf "%s-config" (include "eupf.fullname" .))) }}
{{- $volumes = append $volumes $configVolume }}
{{- end }}
{{- with $volumes }}
volumes:
  {{- toYaml . | nindent 2 }}
{{- end }}

{{- end -}}

{{- define "helpers.pod.volumeMounts" -}}

{{- $mounts := .Values.volumeMounts | default list }}
{{- if .Values.api.tls.existingSecret }}
{{- $mounts = append $mounts (dict "name" "api-tls" "mountPath" "/etc/eupf/tls" "readOnly" true) }}
{{- end }}
{{- if .Values.config.enabled }}
{{- $configMount := dict "name" "config" "mountPath" .Values.config.mountPath }}
{{- $mounts = append $mounts $configMount }}
{{- end }}
{{- with $mounts }}
volumeMounts:
  {{- toYaml . | nindent 2 }}
{{- end }}

{{- end -}}

{{- define "eupf.apiSecretName" -}}
{{- .Values.api.existingSecret | default (printf "%s-api" (include "eupf.fullname" .)) -}}
{{- end -}}

{{- define "helpers.pod.cli" -}}
{{- if .Values.cli.enabled }}
- name: cli
  image: {{ .Values.cli.image | quote }}
  env:
    - name: CLI_EUPF_ADDR
      value: {{ printf "%s://127.0.0.1:%v/api/v1" (ternary "https" "http" (not (empty .Values.api.tls.existingSecret))) .Values.service.port | quote }}
    {{- if and .Values.api.tls.existingSecret .Values.api.tls.caBundleKey }}
    - name: CLI_API_CA_BUNDLE
      value: {{ printf "/etc/eupf/tls/%s" .Values.api.tls.caBundleKey | quote }}
    {{- end }}
    - name: CLI_API_TOKEN
      valueFrom:
        secretKeyRef:
          name: {{ include "eupf.apiSecretName" . }}
          key: api-token
  {{- if .Values.api.tls.existingSecret }}
  volumeMounts:
    - name: api-tls
      mountPath: /etc/eupf/tls
      readOnly: true
  {{- end }}
{{- end }}
{{- end -}}
