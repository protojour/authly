{{/*
Expand the name of the chart.
*/}}
{{- define "authly.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully qualified app name.
*/}}
{{- define "authly.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Allow the release namespace to be overridden
*/}}
{{- define "authly.namespace" -}}
{{- default .Release.Namespace .Values.global.namespace -}}
{{- end -}}

{{/*
Create the name of the service account to use
*/}}
{{- define "authly.serviceaccount.name" -}}
{{- if .Values.serviceAccount.create -}}
    {{ default (include "authly.fullname" .) .Values.serviceAccount.name }}
{{- else -}}
    {{ default "default" .Values.serviceAccount.name }}
{{- end -}}
{{- end -}}

{{/*
Generate an hexadecimal sequence of given length.
Usage: {{ include "authly.randHex" 64 }}
*/}}
{{- define "authly.randHex" -}}
{{- $length := . }}
{{- if or (not (kindIs "int" $length)) (le $length 0) }}
{{- printf "authly.randHex expects a positive integer (%d passed)" $length | fail }}
{{- end}}
{{- printf "%x" (randAscii (divf $length 2 | ceil | int)) | trunc $length }}
{{- end}}
