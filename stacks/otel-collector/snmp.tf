
locals {
  # https://github.com/prometheus/snmp_exporter/blob/main/snmp.yml
  # https://github.com/prometheus/snmp_exporter/tree/main/generator

  # https://hub.docker.com/r/prom/snmp-exporter
  # https://github.com/prometheus/snmp_exporter

  # https://mibbrowser.online/mibdb_search.php?mib=HOST-RESOURCES-V2-MIB

  # http://localhost:9116/snmp?module=hrSystem&target=100.105.67.180
  # http://localhost:9116/snmp?module=hrSystem&target=er-2613e3531e2348a087063887378c2a0f.default-doe.stable.pndrs.de&auth=vyos

}

resource "kubernetes_config_map_v1" "snmp" {
  metadata {
    name      = "prom-snmp-exporter-config"
    namespace = kubernetes_namespace.network.metadata[0].name
  }

  data = {
    "config.yaml" = file("snmp-exporter-config.yaml")

  }
  depends_on = [kubernetes_namespace.network]
}

resource "kubernetes_service_v1" "snmp" {
  metadata {
    name      = "prom-snmp-exporter"
    namespace = kubernetes_namespace.network.metadata[0].name
    labels = {
      app       = "opentelemetry"
      component = "prom-snmp-exporter"
    }
  }

  spec {
    selector = {
      app       = "opentelemetry"
      component = "prom-snmp-exporter"
    }
    port {
      name        = "metrics"
      port        = 9116
      target_port = 9116
    }
  }
}

resource "kubernetes_deployment_v1" "snmp" {
  metadata {
    name      = "prom-snmp-exporter"
    namespace = kubernetes_namespace.network.metadata[0].name
    labels = {
      app       = "opentelemetry"
      component = "prom-snmp-exporter"
    }
  }

  spec {
    selector {
      match_labels = {
        app       = "opentelemetry"
        component = "prom-snmp-exporter"
      }
    }
    min_ready_seconds         = 5
    progress_deadline_seconds = 120
    replicas                  = 1 # TODO
    template {
      metadata {
        labels = {
          app       = "opentelemetry"
          component = "prom-snmp-exporter"
        }
      }
      spec {
        container {
          name = "prom-snmp-exporter"

          image = "${var.docker_repositories.docker_hub}/prom/snmp-exporter:v0.28.0"
          args = [
            "--config.file=/snmp-exporter-config.yaml",
            "--config.file=/etc/snmp_exporter/snmp.yml",
            "--config.expand-environment-variables"
          ]

          # TODO: we will need a custom distro for this for production. https://opentelemetry.io/docs/collector/custom-collector/

          volume_mount {
            name       = "prom-snmp-exporter-config"
            mount_path = "/snmp-exporter-config.yaml"
            sub_path   = "config.yaml"
            read_only  = true
          }

          resources {
            limits = {
              memory = "4Gi"
            }
            requests = {
              cpu    = "200m"
              memory = "400Mi"
            }
          }
          port {
            container_port = 9116
            name           = "metrics"
          }

          env {
            name = "MY_POD_IP"
            value_from {
              field_ref {
                field_path = "status.podIP"
              }
            }
          }
          env {
            name = "SNMP_AUTH_PASSWORD"
            value_from {
              secret_key_ref {
                name = "snmp-credentials"
                key  = "auth-password"
              }
            }
          }
          env {
            name = "SNMP_PRIVACY_PASSWORD"
            value_from {
              secret_key_ref {
                name = "snmp-credentials"
                key  = "privacy-password"
              }
            }
          }
          env {
            name = "K8S_NODE_NAME"
            value_from {
              field_ref {
                field_path = "spec.nodeName"
              }
            }
          }
        }
        volume {
          name = "prom-snmp-exporter-config"
          config_map {
            name = "prom-snmp-exporter-config"
          }
        }
      }
    }
  }

  #   depends_on = [kubernetes_manifest.certs]
}
