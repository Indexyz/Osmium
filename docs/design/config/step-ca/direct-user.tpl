{{- if ne .Type "user" -}}
{{ fail "this provisioner is for SSH user certificates only" }}
{{- end -}}
{{- if or (eq (len .Principals) 0) (gt (len .Principals) 32) -}}
{{ fail "1 to 32 principals are required" }}
{{- end -}}
{
  "type": {{ toJson .Type }},
  "keyId": {{ toJson .KeyID }},
  "principals": {{ toJson .Principals }},
  "extensions": {
{{- if .Token.osmium_extensions }}
  {{- range $i, $ext := .Token.osmium_extensions }}
    {{- if $i }},{{ end }}
    {{ toJson $ext }}: ""
  {{- end }}
{{- else }}
    "permit-pty": "",
    "permit-user-rc": "",
    "permit-port-forwarding": ""
{{- end }}
  }
{{- if .Token.osmium_source_address }},
  "criticalOptions": {
    "source-address": {{ toJson .Token.osmium_source_address }}
  }
{{- end }}
}
