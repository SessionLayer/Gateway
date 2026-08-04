{{- define "sessionlayer-gateway.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "sessionlayer-gateway.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "sessionlayer-gateway.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "sessionlayer-gateway.labels" -}}
helm.sh/chart: {{ include "sessionlayer-gateway.chart" . }}
{{ include "sessionlayer-gateway.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/component: gateway
app.kubernetes.io/part-of: sessionlayer
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
app.kubernetes.io/name carries the unprefixed chart name because the Control
Plane and Agent NetworkPolicies select Gateway pods by exactly this label.
*/}}
{{- define "sessionlayer-gateway.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sessionlayer-gateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "sessionlayer-gateway.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "sessionlayer-gateway.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/* A digest pins the exact bytes; a tag does not. Digest wins when set. */}}
{{- define "sessionlayer-gateway.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end }}

{{- define "sessionlayer-gateway.cpServerName" -}}
{{- default (printf "controlplane.%s.svc" .Release.Namespace) .Values.controlPlane.serverName -}}
{{- end }}

{{- define "sessionlayer-gateway.cpMtlsEndpoint" -}}
{{- default (printf "https://controlplane.%s.svc:9443" .Release.Namespace) .Values.controlPlane.mtlsEndpoint -}}
{{- end }}

{{- define "sessionlayer-gateway.agentAdvertiseUrl" -}}
{{- default (printf "wss://%s.%s.svc:%d" (include "sessionlayer-gateway.fullname" .) .Release.Namespace (int .Values.ssh.agent.listenPort)) .Values.ssh.agent.advertiseUrl -}}
{{- end }}

{{/* Whichever Secret the config file comes from. */}}
{{- define "sessionlayer-gateway.configSecretName" -}}
{{- default (printf "%s-config" (include "sessionlayer-gateway.fullname" .)) .Values.config.existingSecret -}}
{{- end }}

{{- define "sessionlayer-gateway.configSecretKey" -}}
{{- if .Values.config.existingSecret -}}
{{- .Values.config.existingSecretKey -}}
{{- else -}}
gateway.json
{{- end -}}
{{- end }}

{{/*
The rendered gateway.json. Only reached when the operator has not supplied the
whole file in a Secret of their own.
*/}}
{{- define "sessionlayer-gateway.config" -}}
{{- $ssh := dict
      "listen_addr" (printf "0.0.0.0:%d" (int .Values.ssh.listenPort))
      "host_key_path" .Values.ssh.hostKeyPath
      "source_ip_allowlist" .Values.ssh.sourceIpAllowlist
      "agent" (dict
        "listen_addr" (printf "0.0.0.0:%d" (int .Values.ssh.agent.listenPort))
        "advertise_url" (include "sessionlayer-gateway.agentAdvertiseUrl" .))
-}}
{{- $cfg := dict
      "cp_mtls_endpoint" (include "sessionlayer-gateway.cpMtlsEndpoint" .)
      "data_dir" .Values.dataDir
      "ssh" $ssh
      "ha" (dict
        "mode" .Values.ha.mode
        "coordination" .Values.ha.coordination
        "drain" (dict
          "pre_drain_grace_secs" (int .Values.ha.drain.preDrainGraceSecs)
          "deadline_secs" (int .Values.ha.drain.deadlineSecs)
          "readyz_addr" (printf "0.0.0.0:%d" (int .Values.ha.drain.readyzPort))))
      "hardening" (dict
        "landlock" (dict
          "enabled" .Values.hardening.landlock.enabled
          "required" .Values.hardening.landlock.required
          "read_only_paths" .Values.hardening.landlock.readOnlyPaths
          "read_write_paths" .Values.hardening.landlock.readWritePaths)
        "seccomp" (dict "mode" .Values.hardening.seccomp.mode))
-}}
{{- if .Values.bootstrap.enabled -}}
{{- $_ := set $cfg "bootstrap" (dict
      "enrollment_token" (required "sessionlayer-gateway: set bootstrap.enrollmentToken to a token from POST /v1/gateway-enrollment-tokens, or set config.existingSecret to a Secret holding the whole gateway.json, or set bootstrap.enabled=false for an already-enrolled Gateway with a persistent data dir." .Values.bootstrap.enrollmentToken)
      "ca_cert_path" (printf "/etc/sessionlayer/%s" .Values.trustAnchor.key)
      "gateway_name" (required "sessionlayer-gateway: set bootstrap.gatewayName to the name the enrollment token was minted for. HA identity follows this name, so it is not cosmetic." .Values.bootstrap.gatewayName)
      "server_name" (include "sessionlayer-gateway.cpServerName" .)) -}}
{{- end -}}
{{- $cfg = mustMergeOverwrite $cfg .Values.config.overrides -}}
{{- /*
Checked after the overrides, so the guard cannot be walked around by accident.
An empty allowlist is not "no opinion": the Gateway logs a warning and then
accepts SSH from every source address.
*/ -}}
{{- $allow := dig "ssh" "source_ip_allowlist" (list) $cfg -}}
{{- if not (kindIs "slice" $allow) -}}
{{- fail (printf "sessionlayer-gateway: ssh.source_ip_allowlist came out as %s, not a list of CIDRs, and the Gateway would refuse the file at start. --set reads a bracket literal as a string and =null as no value at all; give the list in a values file, or as --set 'ssh.sourceIpAllowlist={10.0.0.0/8}'." (kindOf $allow)) -}}
{{- end -}}
{{- if not $allow -}}
{{- fail "sessionlayer-gateway: ssh.sourceIpAllowlist is empty, which accepts SSH from every source address. Name the client networks that may reach the front door." -}}
{{- end -}}
{{- toPrettyJson $cfg -}}
{{- end }}
