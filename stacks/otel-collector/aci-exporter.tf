resource "kubernetes_config_map" "aci_exporter" {
  metadata {
    name      = "aci-exporter"
    namespace = kubernetes_namespace.network.metadata[0].name
  }
  data = {
    "config.yaml" = file("aci-exporter-config.yaml")
  }
}

resource "kubernetes_deployment" "aci_exporter" {
  metadata {
    name      = "aci-exporter"
    namespace = kubernetes_namespace.network.metadata[0].name
    labels = {
      app = "aci-exporter"
    }
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = "aci-exporter"
      }
    }

    template {
      metadata {
        labels = {
          app = "aci-exporter"
        }
      }

      spec {
        container {
          name  = "aci-exporter"
          image = "europe-west3-docker.pkg.dev/nz-mgmt-shared-artifacts-8c85/quay-io/camillo/aci-exporter:v0.8.0"

          port {
            container_port = 9643
          }

          env {
            name  = "ACI_EXPORTER_PORT"
            value = "9643"
          }

          volume_mount {
            name       = "aci-exporter"
            mount_path = "/etc/aci-exporter"
          }

          env {
            name = "ACI_EXPORTER_FABRICS_FAB1_USERNAME"
            value_from {
              secret_key_ref {
                name = "apstra-credentials"
                key  = "username"
              }
            }
          }
          env {
            name = "ACI_EXPORTER_FABRICS_FAB1_PASSWORD"
            value_from {
              secret_key_ref {
                name = "apstra-credentials"
                key  = "password"
              }
            }
        }
        }

        volume {
          name = "aci-exporter"
          config_map {
            name = kubernetes_config_map.aci_exporter.metadata[0].name
          }
        }
      }
    }
  }
}


resource "kubernetes_service" "aci_exporter" {
  metadata {
    name      = "aci-exporter"
    namespace = kubernetes_namespace.network.metadata[0].name
  }

  spec {
    selector = {
      app = "aci-exporter"
    }

    port {
      name        = "web"
      port        = 9643
      target_port = 9643
      protocol    = "TCP"
    }
  }
}
