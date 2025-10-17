resource "kubernetes_secret" "proxy_json_exporter_credentials" {
  metadata {
    name      = "proxy-json-exporter-credentials"
    namespace = "network"
  }
  type = "Opaque"
  data = {
    username = "obspocuser"
    password = "OBSPoCApstraviewer2025!"
  }
}

resource "kubernetes_secret" "kafka_credentials" {
  metadata {
    name      = "kafka-credentials"
    namespace = "network"
  }
  type = "Opaque"
  data = {
    username = "otel-default-rw"
    password = "fhpPbafRkpmLTtVCv2a60cysPpSD6Awt"
  }
}

resource "kubernetes_secret" "snmp_credentials" {
  metadata {
    name      = "snmp-credentials"
    namespace = "network"
  }
  type = "Opaque"
  data = {
    auth-password    = "vyosobspoc2025auth"
    privacy-password = "vyosobspoc2025priv"
  }
}

resource "kubernetes_secret" "apstra_credentials" {
  metadata {
    name      = "apstra-credentials"
    namespace = "network"
  }
  type = "Opaque"
  data = {
    username = "obsacilocal"
    password = "gc3AYzdqVgxZ"
  }
}