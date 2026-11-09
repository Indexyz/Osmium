{{- if ne .Type "user" -}}
{{ fail "this provisioner is for SSH user certificates only" }}
{{- end -}}
{{- if ne (len .Principals) 1 -}}
{{ fail "exactly one target principal is required" }}
{{- end -}}
{
  "type": {{ toJson .Type }},
  "keyId": {{ toJson .KeyID }},
  "principals": {{ toJson .Principals }},
  "extensions": {
    "permit-pty": ""
  },
  "criticalOptions": {}
}
